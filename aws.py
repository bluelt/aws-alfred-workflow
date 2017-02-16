"""
A collection of commands used in this workflow
"""

import click
import json
import os
import sys
import time
import uuid
from botocore.exceptions import ClientError
from datetime import datetime
from numbers import Number

# ---------------------CONFIG-----------------------------

KEYS = {'Key': u'Key', 'Tags': u'Tags', 'Value': u'Value', 'InstanceId': u'InstanceId', 'InstanceType': u'InstanceType',
        'PrivateIpAddress': u'PrivateIpAddress', 'PublicIpAddress': u'PublicIpAddress', 'Instances': u'Instances',
        'ImageId': u'ImageId', 'PrivateDnsName': u'PrivateDnsName', 'PublicDnsName': u'PublicDnsName', 'SubnetId': u'SubnetId', 'VpcId': u'VpcId'}


# instance sample
# {u'OwnerId': '477928018413', u'ReservationId': 'r-083b6c576bdc6ff7c', u'Groups': [], u'Instances': [{u'Monitoring':
# {u'State': 'disabled'}, u'PublicDnsName': '', u'State': {u'Code': 16, u'Name': 'running'}, u'EbsOptimized': True,
# u'LaunchTime': datetime.datetime(2016, 12, 15, 3, 2, 46, tzinfo=tzutc()), u'PrivateIpAddress': '10.213.0.154', u'ProductCodes': [],
# u'VpcId': 'vpc-c310b0aa', u'StateTransitionReason': '', u'InstanceId': 'i-01d82bbdf4c65472b', u'ImageId': 'ami-878a40e9',
# u'PrivateDnsName': 'ip-10-213-0-154.ap-northeast-2.compute.internal', u'KeyName': 'deathwing-rancher',
# u'SecurityGroups': [{u'GroupName': 'product-dev-PrivateSecurityGroup-RUS69VVMZRCO', u'GroupId': 'sg-f0019099'}],
# u'ClientToken': 'XnjlV1481594654310', u'SubnetId': 'subnet-3cdf7255', u'InstanceType': 'm4.large',
# u'NetworkInterfaces': [{u'Status': 'in-use', u'MacAddress': '02:5b:a1:79:b3:2d', u'SourceDestCheck': True,
# u'VpcId': 'vpc-c310b0aa', u'Description': 'Primary network interface', u'NetworkInterfaceId': 'eni-cf9556a4',
# u'PrivateIpAddresses': [{u'PrivateDnsName': 'ip-10-213-0-154.ap-northeast-2.compute.internal', u'Primary': True,
# u'PrivateIpAddress': '10.213.0.154'}], u'PrivateDnsName': 'ip-10-213-0-154.ap-northeast-2.compute.internal',
# u'Attachment': {u'Status': 'attached', u'DeviceIndex': 0, u'DeleteOnTermination': True, u'AttachmentId': 'eni-attach-15d102a8',
# u'AttachTime': datetime.datetime(2016, 12, 13, 2, 4, 14, tzinfo=tzutc())},
# u'Groups': [{u'GroupName': 'product-dev-PrivateSecurityGroup-RUS69VVMZRCO', u'GroupId': 'sg-f0019099'}], u'Ipv6Addresses': [],
# u'SubnetId': 'subnet-3cdf7255', u'OwnerId': '477928018413', u'PrivateIpAddress': '10.213.0.154'}], u'SourceDestCheck': True,
# u'Placement': {u'Tenancy': 'default', u'GroupName': '', u'AvailabilityZone': 'ap-northeast-2a'}, u'Hypervisor': 'xen',
# u'BlockDeviceMappings': [{u'DeviceName': '/dev/sda1', u'Ebs': {u'Status': 'attached', u'DeleteOnTermination': True,
# u'VolumeId': 'vol-05671d855f6257e0c', u'AttachTime': datetime.datetime(2016, 12, 13, 2, 4, 15, tzinfo=tzutc())}},
# {u'DeviceName': '/dev/xvdb', u'Ebs': {u'Status': 'attached', u'DeleteOnTermination': True, u'VolumeId': 'vol-0315f49f50edbe7ac', u'AttachTime': datetime.datetime(2016, 12, 13, 2, 4, 15, tzinfo=tzutc())}}, {u'DeviceName': '/dev/xvdc', u'Ebs': {u'Status': 'attached', u'DeleteOnTermination': True, u'VolumeId': 'vol-02ae9986236ddc894', u'AttachTime': datetime.datetime(2016, 12, 13, 2, 4, 15, tzinfo=tzutc())}}, {u'DeviceName': '/dev/xvdd', u'Ebs': {u'Status': 'attached', u'DeleteOnTermination': True, u'VolumeId': 'vol-003694c42b0eb1116', u'AttachTime': datetime.datetime(2016, 12, 13, 2, 4, 15, tzinfo=tzutc())}}], u'Architecture': 'x86_64', u'RootDeviceType': 'ebs', u'RootDeviceName': '/dev/sda1', u'VirtualizationType': 'hvm', u'Tags': [{u'Value': 'maur-core-api-2', u'Key': 'Name'}], u'AmiLaunchIndex': 0}]}
# Override these next 2 functions to change the title/subtitle in the instance list
def instance_title(instance):
    """Given an instance, returns the title of the list item as a string"""

    tags = {t[KEYS['Key']]: t[KEYS['Value']] for t in instance.get(KEYS['Tags'])}
    return ' '.join([
        tags.get('Name', ''),
        tags.get('aws:autoscaling:groupName', ''),
    ])


def instance_subtitle(instance):
    """Given an instance, returns the subtitle of the list item as a string"""
    return ' '.join([
        instance.get(KEYS['InstanceId']),
        instance.get(KEYS['InstanceType']),
        getattr(instance, KEYS['PrivateIpAddress'], None) or getattr(instance, KEYS['PublicIpAddress'], None) or ''
    ])


DEFAULT_OUTPUT_FIELD = 'private_ip_address'
CACHE_DIR = 'caches'
CREDS_CACHE_FILE = os.path.join(CACHE_DIR, "creds.cache")
CREDS_CACHE_EXPIRATION_WINDOW = 2  # seconds
CONFIG_CACHE_FILE = os.path.join(CACHE_DIR, "boto-config.cache")
INSTANCES_CACHE_EXT = "aws-instances.cache"
INSTANCES_CACHE_MAX_AGE = 40  # seconds


# --------------------------------------------------------

@click.group()
def cli():
    """Main group for other subcommands"""
    # Make sure cache dir exists
    if not os.path.exists(CACHE_DIR):
        os.mkdir(CACHE_DIR)


# --------------------------------------------------------

@cli.command()
def get_profiles():
    """Print a alfred-formatted list of available boto profiles"""
    profiles = get_boto_config().keys()

    result = {
        "items": [
            {
                "uid": profile,
                "title": profile,
                "arg": profile,
                "autocomplete": profile,
            }
            for profile in profiles
            ]
    }

    click.echo(json.dumps(result))


# --------------------------------------------------------

@cli.command()
@click.argument('profile')
def check_profile(profile):
    """
    If no MFA is necessary for <profile>, exits with status 2
    If an MFA is neccessary for <profile> but the cached temporary credentials are expired, exit with status 1
    If an MFA is required for <profile> and the cached temporary credentials are still valid, exit with status 0
    """
    config = get_boto_config()[profile]

    if 'role_arn' not in config:
        sys.exit(2)  # No MFA necessary, go straight to search

    creds_cache = get_creds_cache(profile)

    now = time.time()
    if creds_cache is None or creds_cache['expires'] - CREDS_CACHE_EXPIRATION_WINDOW <= now:
        sys.exit(1)  # Creds are expired, prompt user for MFA

    sys.exit(0)  # Creds are still valid, move along


# --------------------------------------------------------

@cli.command()
@click.argument('profile')
@click.argument('token')
def prompt_for_mfa(profile, token):
    """
    Prompt a user for their MFA token, retrieve temporary credentials,
    store them in the cache, then pass them to the next stage
    """
    if len(token) < 6:
        click.echo(json.dumps({'items': [{'title': '...', 'valid': False}]}))
    elif len(token) > 6:
        click.echo(json.dumps({'items': [{'title': 'Token too long!', 'valid': False}]}))
    else:
        try:
            temp_creds = get_temp_creds(profile, token)
        except ClientError:
            click.echo(json.dumps({'items': [{'title': 'Invalid token!', 'valid': False}]}))
        except:
            click.echo(json.dumps({'items': [{'title': 'Unexpected error!', 'valid': False}]}))
        else:
            update_creds_cache(profile, temp_creds)
            click.echo(json.dumps({
                "items": [{
                    "title": "Continue",
                    "arg": "PLACEHOLDER",  # If "arg" is not set, the option will not be selectable
                }]
            }))


def get_temp_creds(profile, token):
    """Use STS to retrieve temporary credentials for <profile>"""
    from boto3 import Session  # Late import because importing boto3 is slow

    config = get_boto_config()[profile]
    hub_client = Session(profile_name=config['source_profile']).client('sts')

    response = hub_client.assume_role(
        RoleArn=config['role_arn'],
        RoleSessionName='alfed-aws-{}@{}'.format(str(uuid.uuid4())[:8], profile),
        DurationSeconds=3600,
        SerialNumber=config['mfa_serial'],
        TokenCode=token,
    )

    temp_creds = response['Credentials']

    return {
        'access_key': temp_creds['AccessKeyId'],
        'secret_key': temp_creds['SecretAccessKey'],
        'session_token': temp_creds['SessionToken'],
        # Python's datetime lib is dumb and doesn't know how to turn timezone-aware datetimes
        # into epoch timestamps. Since the datetime boto returns and the datetime returned
        # by datetime.utcfromtimestamp() are both in UTC, this is safe.
        'expires': (temp_creds['Expiration'].replace(tzinfo=None) - datetime.utcfromtimestamp(0)).total_seconds(),
    }


def update_creds_cache(profile, dct):
    """Update the creds cache with <dct> as its new value"""
    if os.path.exists(CREDS_CACHE_FILE):
        with open(CREDS_CACHE_FILE, 'r') as f:
            creds = json.load(f)
        creds[profile] = dct
        new_creds = creds
    else:
        new_creds = {profile: dct}

    with open(CREDS_CACHE_FILE, 'w') as f:
        json.dump(new_creds, f)


# --------------------------------------------------------

@cli.command()
@click.option('--profile')
@click.argument('query')
def search_for_instances(profile, query):
    """
    Print an alfred-formatted list of instances in the AWS account given by <profile> that match <query>
    """
    temp_creds = get_creds_cache(profile)
    query = query.split()
    result = {"items": []}

    instances = get_instances(profile, temp_creds, query)

    for instance in instances:
        inst = instance.get(KEYS['Instances'])[0]
        title = instance_title(inst)
        subtitle = instance_subtitle(inst)

        entry = {
            'uid': inst.get(KEYS['InstanceId']),
            'title': title or '',  # Protect against potential None (unserializable)
            'subtitle': subtitle or '',
            'mods': {
                'shift': {
                    # Pass the selected result as a string to the next node, which filters it
                    # 'arg': json.dumps(extract_output_fields(inst)),
                    'subtitle': "More options",
                    'valid': True
                }
            }
        }

        # If the instance doesn't have a private IP address, the only valid action is "More options"
        arg = ({'arg': inst.get(KEYS['PrivateIpAddress'])})
        entry.update(arg)

        # result['items'].append(entry)

        ent = {'uid': 'test', 'title': 'mytytle', 'subtitle': 'mysub', 'mods': {'shift': {'valid': True}}}
        result['items'].append(entry)

    click.echo(json.dumps(result))


def get_instances(profile, temp_creds, query):
    """Get a list of all instances in the account given by <profile> from AWS"""

    import boto3
    ec2 = boto3.client('ec2')
    tag_value = '*' + query[0] + '*'
    filters = [{'Name': 'tag:Name', 'Values': [tag_value]}]
    inst = ec2.describe_instances(Filters=filters)
    instances = list(dict(inst).get('Reservations'))

    return instances


def extract_output_fields(instance):
    return {
        'items': [
            {
                'uid': instance.get(KEYS['InstanceId']),
                'title': instance.get(KEYS['ImageId']),
                'subtitle': instance.get(KEYS['InstanceType']),
                'arg': instance.get(KEYS['PrivateIpAddress']),
            }
        ]
    }


# --------------------------------------------------------

@cli.command()
@click.argument('spec')
@click.argument('query')
def filter_output_fields(spec, query):
    """Filters on both title and subtitle, unlike default Alfred filtering, which filters only on title"""
    spec = json.loads(spec)

    results = {
        "items": [
            item for item in spec['items']
            if query in item.get('title', '').lower() or query in item.get('subtitle', '').lower()
            ]
    }

    click.echo(json.dumps(results))


# --------------- Shared helper functions-----------------

def get_creds_cache(profile):
    """Return the creds cache for a particular profile"""
    if os.path.exists(CREDS_CACHE_FILE):
        with open(CREDS_CACHE_FILE, 'r') as f:
            return json.load(f)[profile]
    else:
        return None


def get_boto_config():
    """Return full boto config. Caches responses for performance."""
    cf_files = filter(os.path.exists, map(os.path.expanduser,
                                          ['~/.aws/config', '~/.aws/credentials', '/etc/boto.cfg', '~/.boto']))
    env_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'AWS_DEFAULT_REGION', 'AWS_PROFILE', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE',
                'AWS_CA_BUNDLE', 'AWS_METADATA_SERVICE_TIMEOUT', 'AWS_METADATA_SERVICE_NUM_ATTEMPTS',
                'AWS_DATA_PATH']

    if os.path.exists(CONFIG_CACHE_FILE):
        with open(CONFIG_CACHE_FILE) as f:
            cache = json.load(f)

        cache_invalid = (
            any(os.stat(cf).st_mtime > os.stat(CONFIG_CACHE_FILE).st_mtime for cf in cf_files) or
            any(os.environ.get(cv) != cache['env'].get(cv) for cv in env_vars)
        )
    else:
        cache_invalid = True

    if cache_invalid:
        from boto3 import Session  # late import because importing boto3 is slow
        config = Session()._session.full_config['profiles']
        with open(CONFIG_CACHE_FILE, 'w') as f:
            json.dump({'config': config, 'env': {cv: os.environ.get(cv) for cv in env_vars}}, f)
        return config

    else:
        return cache['config']


class SerializableInstance(object):
    """A wrapper for Boto3 Instance resources that is pickleable"""

    def __init__(self, instance):
        for prop in dir(instance):
            val = getattr(instance, prop)
            if self._is_serializable(val):
                setattr(self, prop, val)

    def _is_serializable(self, val):
        if isinstance(val, Number):
            return True
        elif isinstance(val, str):
            return not val.startswith('__')
        elif isinstance(val, dict):
            return all(self._is_serializable(v) for v in val.values())
        elif isinstance(val, list):
            return all(self._is_serializable(i) for i in val)
        else:
            return False


if __name__ == '__main__':
    cli()
