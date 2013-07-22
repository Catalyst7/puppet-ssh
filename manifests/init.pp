# ssh_auth_key_master
#
# Create/regenerate/remove a key pair on the keymaster.
# This definition is private, i.e. it is not intended to be called directly by users.
# ssh::auth::key calls it to create virtual keys, which are realized in ssh::auth::keymaster.

define ssh_auth_key_master ($ensure, $force, $keytype, $length, $maxdays, $mindate) {

  Exec { path => "/usr/bin:/usr/sbin:/bin:/sbin" }
  File {
    owner => puppet,
    group => puppet,
    mode  => 600,
  }

  $keydir = "${ssh::auth::keymaster_storage}/${title}"
  $keyfile = "${keydir}/key"

  file {
    "$keydir":
      ensure => directory,
      mode   => 644;
    "$keyfile":
      ensure => $ensure;
    "${keyfile}.pub":
      ensure => $ensure,
      mode   => 644;
  }

  if $ensure == "present" {

    # Remove the existing key pair, if
    # * $force is true, or
    # * $maxdays or $mindate criteria aren't met, or
    # * $keytype or $length have changed

    $keycontent = file("${keyfile}.pub", "/dev/null")
    if $keycontent {

      if $force {
        $reason = "force=true"
      }
      if !$reason and $mindate and generate("/usr/bin/find", $keyfile, "!", "-newermt", "${mindate}") {
        $reason = "created before ${mindate}"
      }
      if !$reason and $maxdays and generate("/usr/bin/find", $keyfile, "-mtime", "+${maxdays}") {
        $reason = "older than ${maxdays} days"
      }
      if !$reason and $keycontent =~ /^ssh-... [^ ]+ (...) (\d+)$/ {
        if       $keytype != $1 { $reason = "keytype changed: $1 -> $keytype" }
        else { if $length != $2 { $reason = "length changed: $2 -> $length" } }
      }
      if $reason {
        exec { "Revoke previous key ${title}: ${reason}":
          command => "rm $keyfile ${keyfile}.pub",
          before  => Exec["Create key $title: $keytype, $length bits"],
        }
      }
    }

    # Create the key pair.
    # We "repurpose" the comment field in public keys on the keymaster to
    # store data about the key, i.e. $keytype and $length.  This avoids
    # having to rerun ssh-keygen -l on every key at every run to determine
    # the key length.
    exec { "Create key $title: $keytype, $length bits":
      command => "ssh-keygen -t ${keytype} -b ${length} -f ${keyfile} -C \"${keytype} ${length}\" -N \"\"",
      user    => "puppet",
      group   => "puppet",
      creates => $keyfile,
      require => File[$keydir],
      before  => File[$keyfile, "${keyfile}.pub"],
    }

  } # if $ensure  == "present"

} # define ssh_auth_key_master


##########################################################################


# ssh_auth_key_client
#
# Install a key pair into a user's account.
# This definition is private, i.e. it is not intended to be called directly by users.

define ssh_auth_key_client ($ensure, $filename, $group, $home, $user) {

  File {
    owner   => $user,
    group   => $group,
    mode    => 600,
#    require => [ User[$user], File[$home]],
  }

  $key_src_file = "${ssh::auth::keymaster_storage}/${title}/key" # on the keymaster
  $key_tgt_file = "${home}/.ssh/${filename}" # on the client

  $key_src_content_pub = file("${key_src_file}.pub", "/dev/null")
  if $ensure == "absent" or $key_src_content_pub =~ /^(ssh-...) ([^ ]+)/ {
    $keytype = $1
    $modulus = $2
    file {
      $key_tgt_file:
        ensure  => $ensure,
        content => file($key_src_file, "/dev/null");
      "${key_tgt_file}.pub":
        ensure  => $ensure,
        content => "$keytype $modulus $title\n",
        mode    => 644;
    }
  } else {
    notify { "Private key file $key_src_file for key $title not found on keymaster; skipping ensure => present": }
  }

} # define ssh_auth_key_client


##########################################################################


# ssh_auth_key_server
#
# Install a public key into a server user's authorized_keys(5) file.
# This definition is private, i.e. it is not intended to be called directly by users.

define ssh_auth_key_server ($ensure, $group, $home, $options, $user) {

  # on the keymaster:
  $key_src_dir = "${ssh::auth::keymaster_storage}/${title}"
  $key_src_file = "${key_src_dir}/key.pub"
  # on the server:
  $key_tgt_file = "${home}/.ssh/authorized_keys"

  File {
    owner   => $user,
    group   => $group,
    require => User[$user],
    mode    => 600,
  }
  Ssh_authorized_key {
    user   => $user,
    target => $key_tgt_file,
  }

  if $ensure == "absent" {
    ssh_authorized_key { $title: ensure => "absent" }
  }
  else {
    $key_src_content = file($key_src_file, "/dev/null")
    if ! $key_src_content {
      notify { "Public key file $key_src_file for key $title not found on keymaster; skipping ensure => present": }
    } else { if $ensure == "present" and $key_src_content !~ /^(ssh-...) ([^ ]*)/ {
      err("Can't parse public key file $key_src_file")
      notify { "Can't parse public key file $key_src_file for key $title on the keymaster: skipping ensure => $ensure": }
    } else {
      $keytype = $1
      $modulus = $2
      ssh_authorized_key { $title:
        ensure  => "present",
        type    => $keytype,
        key     => $modulus,
        options => $options ? { "" => undef, default => $options },
      }
    }} # if ... else ... else
  } # if ... else

} # define ssh_auth_key_server


##########################################################################


# ssh_auth_key_namecheck
#
# Check a name (e.g. key title or filename) for the allowed form

define ssh_auth_key_namecheck ($parm, $value) {
  if $value !~ /^[A-Za-z0-9]/ {
    fail("ssh::auth::key: $parm '$value' not allowed: must begin with a letter or digit")
  }
  if $value !~ /^[A-Za-z0-9_.:@-]+$/ {
    fail("ssh::auth::key: $parm '$value' not allowed: may only contain the characters A-Za-z0-9_.:@-")
  }
} # define namecheck
