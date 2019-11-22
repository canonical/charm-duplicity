import os
import pytest
import subprocess
import stat
import asyncio
import time
import string
import random
from tempfile import NamedTemporaryFile

# Treat all tests as coroutines
pytestmark = pytest.mark.asyncio

JUJU_REPO = os.getenv('JUJU_REPOSITORY', '.').rstrip('/')
SERIES = ['xenial',
          'bionic',
         ]
SOURCES = [('local', '{}/builds/duplicity'.format(JUJU_REPO)),
           # ('jujucharms', 'cs:...'),
           ]
PRINCIPALS = ['ubuntu',
              'grafana']


# Custom fixtures
# Parameterized fixtures
@pytest.fixture(params=SERIES, scope="function")
def series(request):
    return request.param


@pytest.fixture(params=PRINCIPALS, scope="module")
def principal_name(request):
    return request.param


@pytest.fixture(params=SOURCES, ids=[s[0] for s in SOURCES], scope="module")
def source(request):
    return request.param

# Setup Test Models
@pytest.fixture()
async def app(model, series, source):
    """
    This fixture tries to get and return the application object if it exists.
    """
    application_name = '{}-{}-{}'.format("duplicity", series, source[0])
    return model.applications.get(application_name)


@pytest.fixture(scope="module", autouse=True)
async def deploy_backup_host(model):
    """
    This is an autouse fixture which initiates non-blocking creation of a
    backup host to be used during testing.
    """
    application_name = "backup-test-host"
    if not model.applications.get(application_name):
        await model.deploy("ubuntu",
                           application_name=application_name,
                           series="bionic")


@pytest.fixture()
async def backup_host(model):
    """ Gets and returns lib juju application object for the backup host """
    application_name = "backup-test-host"
    # TODO This should wait until host deployment is complete
    return model.applications.get(application_name)


@pytest.fixture(scope="module", autouse=True)
async def deploy_all_principals(model):
    """ This is an autouse fixture that tries to pre-empt creation of all
    principal applications so tests will run slightly faster """
    for series in SERIES:
        if not isinstance(series, str):
            # Skip the non str param, its a pytest.mark obj
            continue
        for principal_name in PRINCIPALS:
            application_name = '{}-{}'.format(principal_name, series)
            principal = model.applications.get(application_name)
            if not principal:
                await model.deploy(principal_name,
                                   application_name=application_name,
                                   series=series)


@pytest.fixture()
async def principal_app(model, principal_name, series):
    """ Fixture to retrieve the the deployed principal application """
    application_name = '{}-{}'.format(principal_name, series)
    return model.applications.get(application_name)


@pytest.mark.skipif(os.getenv("PYTEST_MODEL") is not None and
                    os.getenv("PYTEST_KEEP_MODEL") is not None and
                    os.getenv("PYTEST_KEEP_MODEL").lower() == 'true',
                    reason="Applications are already deployed.")
@pytest.mark.parametrize("seriesx",  SERIES + [pytest.param('cosmic',
                                    marks=pytest.mark.xfail(
                                    reason='Charm version not supported'))])
async def test_deploy_duplicity_application(model, source, seriesx):
    """
    Test function that verifies successful deployment of the duplicity
    application to the juju model.
    """
    # unfortunately juju lib doesnt like to create subordinates, using sp
    application_name = '{}-{}-{}'.format("duplicity", seriesx, source[0])
    cmd = ['juju', 'deploy', source[1], '-m', model.info.name, '--series',
           seriesx, application_name]
    subprocess.check_call(cmd)
    await asyncio.sleep(3)
    assert model.applications.get(application_name)
    app = model.applications.get(application_name)
    await model.block_until(lambda: app.status in ['waiting', 'active'])


async def test_deploy_duplicity_unit(model, principal_app, app):
    """ Test function that verifies successful deployment of duplicity
    unit to the model by adding charm relations between a principal
    application, and the duplicity charm as a subordinate.
    """
    relation = "{}:general-info {}:juju-info".format(app.name,
                                                     principal_app.name)
    if list(filter(lambda x: x.key == relation, app.relations)):
        pytest.skip("Relation {} already exists.".format(relation))
    else:
        await principal_app.add_relation("juju-info", app.name)
    rel = filter(lambda rel: rel.key == relation, app.relations)
    assert rel


async def test_charm_upgrade(model, app):
    if app.name.endswith('local'):
        pytest.skip("No need to upgrade the local deploy")
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == 'idle')
    subprocess.check_call(['juju',
                           'upgrade-charm',
                           '--switch={}'.format(SOURCES[0][1]),
                           '-m', model.info.name,
                           app.name,
                           ])
    await model.block_until(lambda: unit.agent_status == 'executing')


@pytest.mark.parametrize("backend", ["rsync",
                                     "ssh",
                                     "scp",
                                     "ftp",
                                     "sftp",
                                     "s3",
                                     "file",
                                     "nonsense",
                                     ""
                                     ])
async def test_duplicity_status_backend(model, app, backend):
    """
    This test checks for expected charm states when different config values
    are applied for backend.

      Charm will begin blocked when:
      - No backend type is supplied or bad value
      - Backend is set to 's3' but: [ aws_access_key_id == "" ||
                                      aws_secret_access_key == "" ]
      - Encryption type is unset: [ disable_encryption == False &&
                                    encryption_passphrase == "" &&
                                    gpg_public_key == "" ]
    """
    #await until the app is finished deploying before attmpting config change
    await model.block_until(lambda: app.status != 'waiting', timeout=300)
    await model.block_until(lambda: app.status != 'maintenance', timeout=300)
    assert app.status != "error"
    subprocess.check_call(['juju',
                           'config',
                           app.name,
                           '-m', model.info.name,
                           'disable_encryption=True',
                           "backend={}".format(backend),
                           'remote_backup_url=placeholder/path'])
    time.sleep(5)
    if backend in ["ftp", "sftp", "ssh", "scp", "rsync", "file"]:
        # state should go active
        await model.block_until(lambda: app.status == 'active', timeout=300)
    elif backend == "s3":
        # This should be blocked. Set the aws credentials to unblock it.
        await model.block_until(lambda: app.status == 'blocked', timeout=300)
        subprocess.check_call(['juju',
                               'config',
                               app.name,
                               '-m', model.info.name,
                               'backend={}'.format(backend),
                               'aws_secret_access_key=fakekeydecafbadbeef',
                               'aws_access_key_id=awsfakekeyid'])
        time.sleep(5)

        await model.block_until(lambda: app.status == 'active', timeout=300)
    else:
        # blocked
        await model.block_until(lambda: app.status == 'blocked', timeout=300)
    assert app.status != "error"


@pytest.mark.parametrize("encryption_passphrase", ["", "easy-password"])
@pytest.mark.parametrize("gpg_public_key", ["", "gpg-easy-key"])
@pytest.mark.parametrize("disable_encryption", [True, False])
async def test_duplicity_status_encryption_settings(model, app,
                                                    encryption_passphrase,
                                                    gpg_public_key,
                                                    disable_encryption):
    """
    Test function that checks that the application blocks when not provided
    with an encryption passphrase, gpg public key, and encryption is not
    disabled.
    """
    subprocess.check_call(['juju',
                           'config',
                           app.name,
                           '-m', model.info.name,
                           'backend=ssh',
                           'remote_backup_url=placeholder/path',
                           'disable_encryption={}'.format(disable_encryption),
                           "gpg_public_key={}".format(gpg_public_key),
                           "encryption_passphrase={}".format(
                                                    encryption_passphrase)])
    await model.block_until(lambda: app.status not in ['maintenance',
                                                       'waiting'], timeout=300)
    if not disable_encryption and not gpg_public_key and \
       not encryption_passphrase:
        time.sleep(5)
        await model.block_until(lambda: app.status == 'blocked', timeout=300)
    else:
        time.sleep(5)
        await model.block_until(lambda: app.status == 'active', timeout=300)


@pytest.fixture
def make_backup_test_data(model, app, tmpdir):
    """ Creates test data in local test temp dir, then puts the data on the
    units to test backups. The test data consists of three regular text filled
    with a few hundred random Bytes.

    :returns: str - path to be used as the source directory on each unit
    """
    # make the local test data directory to be copied to the units
    test_data_dir = os.path.join(tmpdir.strpath, "duplicity-testdata")
    try:
        os.mkdir(test_data_dir)
    except:
        pass

    # Use a directory that ubuntu user has permissions to, otherwise juju scp
    # will fail.
    source_backup_path = "/home/ubuntu/duplicity-backups"
    # set the charms config value for a backup source directory
    subprocess.check_call(["juju", "config", app.name, "-m", model.info.name,
                          "aux_backup_directory={}".format(source_backup_path)
                           ])
    # make the path on the remote units
    for unit in app.units:
        subprocess.check_call(["juju", "ssh", '-m', model.info.name, unit.name,
                               "--", 'mkdir -p {}'.format(source_backup_path),
                               ])
        # I didnt have luck with unit.ssh; Its Not Implemented yet
        # unit.ssh("mkdir -p {}".format(source_backup_path))

    # lambda function to generate a quick 250 Bytes of ASCII
    adddata = lambda: "".join(random.choices(string.ascii_lowercase +
                                             string.ascii_uppercase +
                                             string.digits, k=250))
    for i in range(3):
        #create new tmp file
        with NamedTemporaryFile(mode="w", dir=test_data_dir,
                                delete=False) as f:
            # adds 250 Bytes of random ascii data to a test file
            f.write(adddata())

        # write some new data to the existing files
        for _file in os.listdir(test_data_dir):
            with open(os.path.join(test_data_dir, _file), "w") as f:
                f.write(adddata())

    # scp the files over to the remote hosts
    for unit in app.units:
        for _file in os.listdir(test_data_dir):
            subprocess.check_call(["juju",
                                   "scp",
                                   '-m', model.info.name,
                                   os.path.join(test_data_dir, _file),
                                   "{}:{}".format(unit.name,
                                                  source_backup_path),
                                   ])
    return source_backup_path


@pytest.fixture
def setup_ssh_encryption_keys(tmpdir, model):
    """
    Fixture sets up ssh keypairs across units and the backup test host to
    enable rsync, ssh, scp, and ftp type transfers.
    TODO: Each unit needs ssh-keygen and the test-backup-host needs their
      public keys added to its authorized_hosts file.
      There will be a gotcha regarding first time connection & accepting the
      host key fingerprint. Could be resolved by manually editing the
      known_hosts files on the units.

    :param tmpdir:
    :param model:
    :return:
    """

    pass

def test_do_backup_action(app, setup_ssh_encryption_keys,
                          make_backup_test_data, tmpdir):
    """
    This function tests the do backup action on all units of an application.
    The fixture make_backup_test_data runs three times yielding the remote path
    used as the backup source directory.

    :param app:
    :param setup_ssh_encryption_keys: Fixture that ensures units can talk to
    the backup test host.
    :param make_backup_test_data: Fixture that creates test files and places
    them on the duplicity units for consumption.
    :return:
    """
    # TODO -
    for unit in app.units:
        pass


async def test_verify_action(app):
    unit = app.units[0]
    action = await unit.run_action('verify')
    action = await action.wait()
    assert action.status == 'completed'


async def test_list_current_files_action(app):
    unit = app.units[0]
    action = await unit.run_action('')
    action = await action.wait()
    assert action.status == 'completed'


async def test_execute_duplicity(app, jujutools):
    """ This test runs a call to the duplicity tool to  ensure that it has been
     installed.
    """
    unit = app.units[0]
    cmd = 'duplicity --version'
    results = await jujutools.run_command(cmd, unit)
    assert results['Code'] == '0'


async def test_file_stat(app, jujutools):
    unit = app.units[0]
    path = '/var/lib/juju/agents/unit-{}/charm/metadata.yaml'.format(
        unit.entity_id.replace('/', '-'))
    fstat = await jujutools.file_stat(path, unit)
    assert stat.filemode(fstat.st_mode) == '-rw-r--r--'
    assert fstat.st_uid == 0
    assert fstat.st_gid == 0
