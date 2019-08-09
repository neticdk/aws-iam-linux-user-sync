#!/usr/bin/env python3

# Sync IAM and local users
# Author: Kim Norgaard <kn@netic.dk>

# Description:
#   * fetches public ssh keys for users in an IAM group
#   * populates authorized_keys for each user
#     the public ssh key is the key given for use with CodeCommit
#   * adds the users as local unix users
#     a minimum and maximum uid may (should) be given for each group of users as
#     this ensures the script can be run multiple times for different groups
#     without deleting previously added users
#   * optionally adds users to additional groups
#   * optionally adds users to the sudo group and create a sudoers.d/ file
#   * deletes users no longer existing in the IAM group as local users within
#     the given minimum and maximum UID range
#
# The script requires:
#   * iam:ListUsers
#   * iam:GetGroup
#   * iam:GetSSHPublicKey
#   * iam:ListSSHPublicKeys
#   * iam:GetUser
#   * iam:ListGroups

# By default users are sync'ed from the same account, the instance is running in.
# Using the --iam-role-arn it is possible to assume a role in another account,
# this using IAM in that acccount.

# Depends on: boto3 for python3

# The script is written specifically for debian/ubuntu.

import os
import sys
import re
import pwd
import grp
import logging
import argparse

import boto3

from botocore.exceptions import ClientError


def safe_name(name):
    """
    Converts IAM user names to UNIX user names

    1) Illegal IAM username characters are removed
    2) +/=/,/@ are converted to plus/equals/comma/at
    """
    # IAM users only allow [\w+=,.@-]
    name = re.sub(r'[^\w+=,.@-]+', '', name)
    name = re.sub(r'[+]', 'plus', name)
    name = re.sub(r'[=]', 'equals', name)
    name = re.sub(r'[,]', 'comma', name)
    name = re.sub(r'[@]', 'at', name)
    return name


def get_token_target_account(role_arn, session_name):
    sts_client = boto3.client('sts')
    sts_response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=3600
    )
    return sts_response['Credentials']


logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description="Sync IAM users to local users with SSH access")
parser.add_argument('--iam-role-arn',
                    help='Role to use for fetching users')
parser.add_argument('--user-name-prefix',
                    default='',
                    help='Prefix to prepend to usernames')
parser.add_argument('--iam-group-name',
                    default="LinuxUsers",
                    help='Name of IAM group to sync unprivileged users from')
parser.add_argument('--sudo',
                    action='store_true',
                    help='Creates users capable of sudoing as root')
parser.add_argument('--uid-min',
                    type=int,
                    default=5000,
                    help='Minimum UID to use when adding/deleting users')
parser.add_argument('--uid-max',
                    type=int,
                    default=10000,
                    help='Maximum UID to use when adding/deleting users')
parser.add_argument('--unix-group-name',
                    action='append',
                    default=[],
                    help='Additional names of UNIX groups to create and add the users to')
args = parser.parse_args()

if args.iam_role_arn:
    sts_response = get_token_target_account(args.iam_role_arn, 'new-iam-lookup-session')
    iam = boto3.resource('iam',
                         aws_access_key_id=sts_response['AccessKeyId'],
                         aws_secret_access_key=sts_response['SecretAccessKey'],
                         aws_session_token=sts_response['SessionToken'])
else:
    iam = boto3.resource('iam')

local_users_group = iam.Group(args.iam_group_name)

logger.info("begin processing users")
logger.info("loading iam groups")

try:
    local_users_group.load()
except ClientError as e:
    logger.error("error calling AWS API")
    logger.exception(e)
    sys.exit(1)

users = {}

# Populate user dict with default settings
# IAM usernames can contain characters UNIX usernames can't
# Convert IAM usernames to UNIX-compatible usernames
for user in local_users_group.users.all():
    unix_name = safe_name(args.user_name_prefix+user.name)
    users[user.name] = {
        'unix_name': unix_name
    }

# Get a list of local (real) users. Used later to find out which users to delete.
# idx 0: name, idx 2: uid
local_users = [user[0] for user in pwd.getpwall() if (args.uid_min <= user[2] <= args.uid_max)]

# Delete local users if they are no longer in the IAM groups
user_names_unix = [v['unix_name'] for k, v in users.items()]
users_to_delete = [user for user in local_users if user not in user_names_unix]
if len(users_to_delete):
    logger.info("deleting users no longer authorized...")
    for user in users_to_delete:
        logger.info("{} - deleting user".format(user))
        os.system("/usr/sbin/userdel -rf {}".format(user))
        sudoers_filename = "/etc/sudoers.d/{}".format(user)
        if os.path.isfile(sudoers_filename):
            os.unlink(sudoers_filename)

# Create and populate a new dict for the remaining updates.
# Filter out the users we already deleted.
# If IAM users exist locally, they are marked for update
# else, they are marked for creation.
users_to_update = {}
for k, v in users.items():
    if k in users_to_delete:
        continue
    users_to_update[k] = v
    if args.user_name_prefix+k in local_users:
        users_to_update[k]['action'] = 'update'
    else:
        users_to_update[k]['action'] = 'add'

if args.iam_role_arn:
    iam_client = boto3.client('iam',
                              aws_access_key_id=sts_response['AccessKeyId'],
                              aws_secret_access_key=sts_response['SecretAccessKey'],
                              aws_session_token=sts_response['SessionToken'])
else:
    iam_client = boto3.client('iam')

useradd_cmd = "/usr/sbin/useradd -m -s /bin/bash -k /etc/skel -K UID_MIN={} -K UID_MAX={} {}"
usermod_cmd_add = "/usr/sbin/usermod -a -G {} {}"
userdel_cmd_remove = "/usr/sbin/deluser {} {}"
group_add_cmd = '/usr/sbin/groupadd -f {}'

for group_name in args.unix_group_name:
    unix_groups = [g for g in grp.getgrall() if g.gr_name == group_name]
    if not len(unix_groups):
        logger.info("{} - creating group".format(group_name))
        os.system(group_add_cmd.format(group_name))

# Get a list of users in the "sudo" group. Used to check if users are alrady
# in the group.
current_sudo_users = [g for g in grp.getgrall() if g.gr_name == "sudo"][0].gr_mem

for user, v in users_to_update.items():
    unix_name = v['unix_name']
    if not unix_name or unix_name == "":
        logger.warning("UNIX username is empty for iam-user={}. Skipping.".format(user))
        continue
    logger.info("{} - processing iam user {}".format(unix_name, user))

    if v['action'] == 'add':
        logger.info("{} - adding local user".format(unix_name))
        os.system(useradd_cmd.format(args.uid_min, args.uid_max, unix_name))

    for group_name in args.unix_group_name:
        current_group_users = [g for g in grp.getgrall() if g.gr_name == group_name][0].gr_mem
        if unix_name not in current_group_users:
            logger.info("{} - adding local user to group: {}".format(unix_name, group_name))
            os.system(usermod_cmd_add.format(group_name, unix_name))

    sudoers_filename = "/etc/sudoers.d/{}".format(unix_name)
    home_ssh_dir = "/home/{}/.ssh".format(unix_name)
    authorized_keys_file = "{}/authorized_keys".format(home_ssh_dir)

    # If it's a sudo user...
    if args.sudo:
        # .. add the user to the sudo group, unless already there
        if unix_name not in current_sudo_users:
            logger.info("{} - adding local user to sudo group".format(unix_name))
            os.system(usermod_cmd_add.format('sudo', unix_name))
        # .. add the sudoers.d file unless already there
        if not os.path.isfile(sudoers_filename):
            logger.info("{} - adding local user to {}".format(unix_name, sudoers_filename))
            with open(sudoers_filename, 'w') as f:
                f.write("{} ALL=(ALL) NOPASSWD:ALL\n".format(unix_name))
        os.chmod(sudoers_filename, 0o440)
    # If it's an ordinary user...
    else:
        # .. remove it from the sudo group if it's in there
        if unix_name in current_sudo_users:
            logger.info("{} - removing local user from sudo group".format(unix_name))
            os.system(userdel_cmd_remove.format(unix_name, 'sudo'))
        # .. remove the sudoers.d file if it exists
        if os.path.isfile(sudoers_filename):
            logger.info("{} - removing local user from {}".format(unix_name, sudoers_filename))
            os.unlink(sudoers_filename)

    # Get a list of public ssh keys IDs from IAM
    logger.info("{} - fetching public ssh keys".format(unix_name))
    ssh_public_keys_data = iam_client.list_ssh_public_keys(UserName=user)['SSHPublicKeys']
    ssh_key_ids = [k['SSHPublicKeyId'] for k in ssh_public_keys_data if k['Status'] == 'Active']
    if not len(ssh_key_ids):
        logger.warning("{} - no keys found - user won't be able to login".format(unix_name))
        # Makre sure authorized_keys is deleted if no keys exist in IAM
        if os.path.isfile(authorized_keys_file):
            os.unlink(authorized_keys_file)
        continue

    # Create .ssh
    if not os.path.isdir(home_ssh_dir):
        os.mkdir(home_ssh_dir)
    uid = pwd.getpwnam(unix_name).pw_uid
    gid = pwd.getpwnam(unix_name).pw_gid
    os.chmod(home_ssh_dir, 0o700)
    os.chown(home_ssh_dir, uid, gid)

    # Get a list of public ssh keys from user's authorized_keys file
    authorized_keys_local = []
    if os.path.isfile(authorized_keys_file):
        with open(authorized_keys_file, 'r') as f:
            authorized_keys_local = f.read().splitlines()

    # Get a list of public ssh keys from the IAM user
    authorized_keys_iam = []
    for ssh_key_id in ssh_key_ids:
        ssh_key_data = iam_client.get_ssh_public_key(UserName=user,
                                                     SSHPublicKeyId=ssh_key_id,
                                                     Encoding='SSH').get('SSHPublicKey', {})
        authorized_keys_iam.append(ssh_key_data.get('SSHPublicKeyBody'))

    # Find out which keys to delete
    keys_to_delete = set(authorized_keys_local) - set(authorized_keys_iam)
    # .. and which to add
    keys_to_add = set(authorized_keys_iam) - set(authorized_keys_local)

    # Nothing changed
    if len(keys_to_delete) + len(keys_to_add) == 0:
        logger.info("{} - no public ssh key changes found".format(unix_name))
        continue

    # Just log the deletions... we will re-write the file from the IAM keys if anythings changes
    for ssh_key in keys_to_delete:
        logger.info("{} - revoking key: {}".format(unix_name, ssh_key))

    # Write out new authorized_keys file from IAM keys
    # We could probably compare every single key, but it's probably more expensive than just
    # rewriting the file on every key change event.
    with open(authorized_keys_file, 'w') as f:
        for ssh_key in keys_to_add:
            logger.info("{} - adding key: {}".format(unix_name, ssh_key))
            f.write(ssh_key)
            f.write("\n")

    os.chown(authorized_keys_file, uid, gid)
    os.chmod(authorized_keys_file, 0o600)

logger.info("done processing users")
