# =========
# ssh::auth
# =========
#
# The latest official release and documentation for ssh::auth can always
# be found at http://reductivelabs.com/trac/puppet/wiki/Recipes/ModuleSSHAuth .
#
# Version:          0.3.2
# Release date:     2009-12-29

class ssh::auth {

$keymaster_storage = "/var/lib/keys"

Exec { path => "/usr/bin:/usr/sbin:/bin:/sbin" }
Notify { withpath => false }

}
