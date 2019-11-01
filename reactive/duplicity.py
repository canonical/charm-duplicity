from lib_duplicity import DuplicityHelper
from charmhelpers.core import hookenv
from charms.reactive import set_flag, when_not

helper = DuplicityHelper()


@when_not('duplicity.installed')
def aptinstall_duplicity():
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
    hookenv.status_set('active', '')
    set_flag('duplicity.installed')
