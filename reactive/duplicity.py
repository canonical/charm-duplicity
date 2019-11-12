from lib_duplicity import DuplicityHelper
from charmhelpers.core import hookenv, host
from charms.reactive import set_flag, when_not
from charmhelpers import fetch

helper = DuplicityHelper()


@when_not('duplicity.installed')
def install_duplicity():
    # Do your setup here.
    #
    # If your charm has other dependencies before it can install,
    # add those as @when() clauses above., or as additional @when()
    # decorated handlers below
    #
    # See the following for information about reactive charms:
    #
    #  * https://jujucharms.com/docs/devel/developer-getting-started
    #  * https://github.com/juju-solutions/layer-basic#overview
    #
    hookenv.status_set("maintenance", "Installing duplicity")
    fetch.apt_install("duplicity")
    fetch.apt_install("python-paramiko")
    ##helper.configure_stubby()
    ##host.service_restart(helper.stubby_service)

    hookenv.status_set('active', '')
    set_flag('duplicity.installed')

