#
# Copyright (C) 2016-2017 Wind River Systems, Inc.
#

DEPENDS_append_class-target += " \
    sbsigntool-native \
    libsign-native \
    openssl-native \
    efitools-native \
"

USER_KEY_SHOW_VERBOSE = "1"

UEFI_SB = '${@bb.utils.contains("DISTRO_FEATURES", "efi-secure-boot", "1", "0", d)}'
MOK_SB = '${@bb.utils.contains("DISTRO_FEATURES", "efi-secure-boot", "1", "0", d)}'
IMA = '${@bb.utils.contains("DISTRO_FEATURES", "ima", "1", "0", d)}'
SYSTEM_TRUSTED = '1'

def vprint(str, d):
    if d.getVar('USER_KEY_SHOW_VERBOSE', True) == '1':
        bb.note(str)

def uks_signing_model(d):
    return d.getVar('SIGNING_MODEL', True)

def uks_system_trusted_keys_dir(d):
    set_keys_dir('SYSTEM_TRUSTED', d)
    return d.getVar('SYSTEM_TRUSTED_KEYS_DIR', True) + '/'

def uks_ima_keys_dir(d):
    set_keys_dir('IMA', d)
    return d.getVar('IMA_KEYS_DIR', True) + '/'

def uks_rpm_keys_dir(d):
    # XXX: currently the user rpm pubkey is not supported.
    if uks_signing_model(d) != 'sample':
        return ''

    return d.getVar('RPM_KEYS_DIR', True) + '/'

def sign_efi_image(key, cert, input, output, d):
    import bb.process

    cmd = (' '.join((d.getVar('STAGING_BINDIR_NATIVE', True) + '/sbsign',
                     '--key', key, '--cert', cert,
                     '--output', output, input)))
    vprint("Signing %s with the key %s ..." % (input, key), d)
    vprint("Running: %s" % cmd, d)
    try:
        result, _ = bb.process.run(cmd)
    except bb.process.ExecutionError:
        raise bb.build.FuncFailed('ERROR: Unable to sign %s' % input)

def edss_sign_efi_image(input, output, d):
   # This function will be overloaded in pulsar-binary-release
   pass

def uefi_sb_keys_dir(d):
    set_keys_dir('UEFI_SB', d)
    return d.getVar('UEFI_SB_KEYS_DIR', True) + '/'

def check_uefi_sb_user_keys(d):
    dir = uefi_sb_keys_dir(d)

    for _ in ('PK', 'KEK', 'DB'):
        if not os.path.exists(dir + _ + '.key'):
            vprint("%s.key is unavailable" % _, d)
            return False

        if not os.path.exists(dir + _ + '.pem'):
            vprint("%s.pem is unavailable" % _, d)
            return False

def uefi_sb_sign(input, output, d):
    if d.getVar('UEFI_SB', True) != '1':
        return

    _ = uefi_sb_keys_dir(d)
    sign_efi_image(_ + 'DB.key', _ + 'DB.pem', input, output, d)

def mok_sb_keys_dir(d):
    if d.getVar('MOK_SB', True) != '1':
        return

    set_keys_dir('MOK_SB', d)
    return d.getVar('MOK_SB_KEYS_DIR', True) + '/'

def sb_sign(input, output, d):
    if d.getVar('UEFI_SB', True) != '1':
        return

    if uks_signing_model(d) in ('sample', 'user'):
        # Deal with MOK_SB firstly, as MOK_SB implies UEFI_SB == 1.
        # On this scenario, bootloader is verified by shim_cert.pem
        if d.getVar('MOK_SB', True) == '1':
            mok_sb_sign(input, output, d)
        # UEFI_SB is defined, but MOK_SB is not defined
        # On this scenario, shim is not used, and DB.pem is used to
        # verify bootloader directly.
        else:
            uefi_sb_sign(input, output, d)
    elif uks_signing_model(d) == 'edss':
        edss_sign_efi_image(input, output, d)

def check_mok_sb_user_keys(d):
    dir = mok_sb_keys_dir(d)

    for _ in ('shim_cert', 'vendor_cert'):
        if not os.path.exists(dir + _ + '.key'):
            vprint("%s.key is unavailable" % _, d)
            return False

        if not os.path.exists(dir + _ + '.pem'):
            vprint("%s.pem is unavailable" % _, d)
            return False

def mok_sb_sign(input, output, d):
    if d.getVar('MOK_SB', True) != '1':
        return

    _ = mok_sb_keys_dir(d)
    sign_efi_image(_ + 'vendor_cert.key', _ + 'vendor_cert.pem', input, output, d)

def sel_sign(key, cert, input, d):
    import bb.process

    cmd = (' '.join(('LD_LIBRARY_PATH=' + d.getVar('STAGING_LIBDIR_NATIVE', True) +
           ':$LD_LIBRARY_PATH', d.getVar('STAGING_BINDIR_NATIVE', True) + '/selsign',
           '--key', key, '--cert', cert, input)))
    vprint("Signing %s with the key %s ..." % (input, key), d)
    vprint("Running cmd: %s" % cmd, d)
    try:
        result, _ = bb.process.run(cmd)
    except bb.process.ExecutionError:
        raise bb.build.FuncFailed('ERROR: Unable to sign %s' % input)

def uks_sel_sign(input, d):
    if d.getVar('UEFI_SB', True) != '1':
        return

    if d.getVar('MOK_SB', True) == '1':
        _ = mok_sb_keys_dir(d)
        key = _ + 'vendor_cert.key'
        cert = _ + 'vendor_cert.pem'
    else:
        _ = uefi_sb_keys_dir(d)
        key = _ + 'DB.key'
        cert = _ + 'DB.pem'

    sel_sign(key, cert, input, d)

def check_ima_user_keys(d):
    dir = uks_ima_keys_dir(d)

    for _ in ('key', 'der'):
        if not os.path.exists(dir + 'x509_ima.' + _):
            vprint("%s.pem is unavailable" % _, d)
            return False

def check_system_trusted_keys(d):
    dir = uks_system_trusted_keys_dir(d)

    _ = 'system_trusted_key'
    if not os.path.exists(dir + _ + '.key'):
        vprint("%s.key is unavailable" % _, d)
        return False

    if not os.path.exists(dir + _ + '.pem'):
        vprint("%s.pem is unavailable" % _, d)
        return False

# Convert the PEM to DER format.
def pem2der(input, output, d):
    import bb.process

    cmd = (' '.join((d.getVar('STAGING_BINDIR_NATIVE', True) + '/openssl',
           'x509', '-inform', 'PEM', '-outform', 'DER', 
           '-in', input, '-out', output)))
    try:
        result, _ = bb.process.run(cmd)
    except bb.process.ExecutionError:
        raise bb.build.FuncFailed('ERROR: Unable to convert %s to %s' % (input, output))

# Convert the certificate (PEM formatted) to ESL.
__pem2esl() {
    "${STAGING_BINDIR_NATIVE}/cert-to-efi-sig-list" \
        -g ${UEFI_SIG_OWNER_GUID} "$1" "$2"
}

# Blacklist the sample DB, shim_cert, vendor_cert by default.
__create_default_mok_sb_blacklist() {
    __pem2esl "${SAMPLE_MOK_SB_KEYS_DIR}/shim_cert.pem" \
        "${TMPDIR}/sample_shim_cert.esl"

    __pem2esl "${SAMPLE_MOK_SB_KEYS_DIR}/vendor_cert.pem" \
        "${TMPDIR}/sample_vendor_cert.esl"

    # Cascade the sample DB, shim_cert and vendor_cert to
    # the default vendor_dbx.
    cat "${TMPDIR}/sample_shim_cert.esl" \
        "${TMPDIR}/sample_vendor_cert.esl" >> "${TMPDIR}/blacklist.esl"
}

__create_default_uefi_sb_blacklist() {
    __pem2esl "${SAMPLE_UEFI_SB_KEYS_DIR}/DB.pem" \
        "${TMPDIR}/sample_DB.esl"

    cat "${TMPDIR}/sample_DB.esl" > "${TMPDIR}/blacklist.esl"
}

# Cascade the default blacklist and user specified blacklist if any.
def __create_blacklist(d):
    tmp_dir = d.getVar('TMPDIR', True)

    vprint('Preparing to create the default blacklist %s' % tmp_dir + '/blacklist.esl', d)

    bb.build.exec_func('__create_default_uefi_sb_blacklist', d)
    if d.getVar('MOK_SB', True) == '1':
        bb.build.exec_func('__create_default_mok_sb_blacklist', d) 

    def __pem2esl_dir (dir):
        if not os.path.isdir(dir):
            return

        dst = open(tmp_dir + '/blacklist.esl', 'wb+')

        for _ in os.listdir(dir):
            fn = os.path.join(dir, _)
            if not os.path.isfile(fn):
                continue

            cmd = (' '.join((d.getVar('STAGING_BINDIR_NATIVE', True) + '/cert-to-efi-sig-list',
                   '-g', d.getVar('UEFI_SIG_OWNER_GUID', True), fn,
                   tmp_dir + '/' + _ + '.esl')))
            try:
                result, _ = bb.process.run(cmd)
            except bb.process.ExecutionError:
                vprint('Unable to convert %s' % fn)
                continue

            with open(fn) as src:
                shutil.copyfileobj(src, dst)
                src.close()

        dst.close()

    # Cascade the user specified blacklists.
    __pem2esl_dir(uefi_sb_keys_dir(d) + 'DBX')

    if d.getVar('MOK_SB', True) == '1':
        __pem2esl_dir(mok_sb_keys_dir(d) + 'vendor_dbx')

# To ensure a image signed by the sample key cannot be loaded by a image
# signed by the user key, e.g, preventing the shim signed by the user key
# from loading the grub signed by the sample key, certain sample keys are
# added to the blacklist.
def create_mok_vendor_dbx(d):
    if d.getVar('MOK_SB', True) != '1' or d.getVar('SIGNING_MODEL', True) != 'user':
        return None

    src = d.getVar('TMPDIR', True) + '/blacklist.esl'
    import os
    if os.path.exists(src):
        os.remove(src)

    __create_blacklist(d)

    dst = d.getVar('WORKDIR', True) + '/vendor_dbx.esl'
    import shutil
    shutil.copyfile(src, dst)

    return dst

def create_uefi_dbx(d):
    if d.getVar('UEFI_SB', True) != '1' or d.getVar('SIGNING_MODEL', True) != 'user':
        return None

    src = d.getVar('TMPDIR', True) + '/blacklist.esl'
    import os
    if os.path.exists(src):
        os.remove(src)

    __create_blacklist(d)

    dst = d.getVar('WORKDIR', True) + '/DBX.esl'
    import shutil
    shutil.copyfile(src, dst)

    return dst

create_uefi_sb_user_keys() {
    local deploy_dir="${DEPLOY_DIR_IMAGE}/user-keys/uefi_sb_keys"

    install -d "$deploy_dir"

    # PK is self-signed.
    "${STAGING_BINDIR_NATIVE}/openssl" req -new -x509 -newkey rsa:2048 \
        -sha256 -nodes -days 3650 \
        -subj "/CN=PK Certificate for $USER@`hostname`/" \
        -keyout "$deploy_dir/PK.key" \
        -out "$deploy_dir/PK.pem"

    # KEK is signed by PK. 
    "${STAGING_BINDIR_NATIVE}/openssl" req -new -newkey rsa:2048 \
        -sha256 -nodes \
        -subj "/CN=KEK Certificate for $USER@`hostname`" \
        -keyout "$deploy_dir/KEK.key" \
        -out "${TMPDIR}/KEK.csr"

    "${STAGING_BINDIR_NATIVE}/openssl" x509 -req -in "${TMPDIR}/KEK.csr" \
        -CA "$deploy_dir/PK.pem" -CAkey "$deploy_dir/PK.key" \
        -set_serial 1 -days 3650 -out "$deploy_dir/KEK.pem"

    # DB is signed by KEK.
    "${STAGING_BINDIR_NATIVE}/openssl" req -new -newkey rsa:2048 \
        -sha256 -nodes \
        -subj "/CN=DB Certificate for $USER@`hostname`" \
        -keyout "$deploy_dir/DB.key" \ 
        -out "${TMPDIR}/DB.csr"

    "${STAGING_BINDIR_NATIVE}/openssl" x509 -req -in "${TMPDIR}/DB.csr" \
        -CA "$deploy_dir/KEK.pem" -CAkey "$deploy_dir/KEK.key" \
        -set_serial 1 -days 3650 -out "$deploy_dir/DB.pem"
}

create_mok_sb_user_keys() {
    local deploy_dir="${DEPLOY_DIR_IMAGE}/user-keys/mok_sb_keys"

    install -d "$deploy_dir"

    "${STAGING_BINDIR_NATIVE}/openssl" req -new -x509 -newkey rsa:2048 \
        -sha256 -nodes -days 3650 -subj "/CN=Shim Certificate for $USER@`hostname`/" \
        -keyout "$deploy_dir/shim_cert.key" -out "$deploy_dir/shim_cert.pem"

    "${STAGING_BINDIR_NATIVE}/openssl" req -new -x509 -newkey rsa:2048 \
        -sha256 -nodes -days 3650 -subj "/CN=Vendor Certificate for $USER@`hostname`/" \
        -keyout "$deploy_dir/vendor_cert.key" -out "$deploy_dir/vendor_cert.pem" \
}

create_ima_user_keys() {
    local deploy_dir="${DEPLOY_DIR_IMAGE}/user-keys/ima_keys"

    install -d "$deploy_dir"

    "${STAGING_BINDIR_NATIVE}/openssl" genrsa -out "$deploy_dir/ima_privkey.pem" 2048

    "${STAGING_BINDIR_NATIVE}/openssl" rsa -in "$deploy_dir/ima_privkey.pem" -pubout \
        -out "$deploy_dir/ima_pubkey.pem"
}

def create_user_keys(name, d):
    vprint('Creating the user keys for %s ...' % name, d)
    bb.build.exec_func('create_' + name.lower() + '_user_keys', d)

deploy_uefi_sb_keys() {
    local deploy_dir="${DEPLOY_KEYS_DIR}/uefi_sb_keys"

    if [ x"${UEFI_SB_KEYS_DIR}" != x"$deploy_dir" ]; then
        install -d "$deploy_dir"

        cp -af "${UEFI_SB_KEYS_DIR}"/* "$deploy_dir"
    fi
}

deploy_mok_sb_keys() {
    local deploy_dir="${DEPLOY_KEYS_DIR}/mok_sb_keys"

    if [ x"${MOK_SB_KEYS_DIR}" != x"$deploy_dir" ]; then
        install -d "$deploy_dir"

        cp -af "${MOK_SB_KEYS_DIR}"/* "$deploy_dir"
    fi
}

deploy_ima_keys() {
    local deploy_dir="${DEPLOY_KEYS_DIR}/ima_keys"

    if [ x"${IMA_KEYS_DIR}" != x"$deploy_dir" ]; then
        install -d "$deploy_dir"

        cp -af "${IMA_KEYS_DIR}"/* "$deploy_dir"
    fi
}

deploy_system_trusted_keys() {
    local deploy_dir="${DEPLOY_KEYS_DIR}/system_trusted_keys"

    if [ x"${SYSTEM_TRUSTED_KEYS_DIR}" != x"$deploy_dir" ]; then
        install -d "$deploy_dir"

        cp -af "${SYSTEM_TRUSTED_KEYS_DIR}"/* "$deploy_dir"
    fi
}

def deploy_keys(name, d):
    d.setVar('DEPLOY_KEYS_DIR', d.getVar('DEPLOY_DIR_IMAGE', True) + '/' + \
             d.getVar('SIGNING_MODEL', True) + '-keys')
    bb.build.exec_func('deploy_' + name.lower() + '_keys', d)

def sanity_check_user_keys(name, may_exit, d):
    if name == 'UEFI_SB':
        _ = check_uefi_sb_user_keys(d)
    elif name == 'MOK_SB':
        _ = check_mok_sb_user_keys(d)
    elif name == 'IMA':
        _ = check_ima_user_keys(d)
    elif name == 'SYSTEM_TRUSTED':
        _ = check_system_trusted_keys(d)
    else:
        _ = False
        may_exit = True

    if _ == False:
        if may_exit:
            raise bb.build.FuncFailed('ERROR: Unable to find user key for %s ...' % name)

        vprint('Failed to check the user keys for %s ...' % name, d)

    return _

# *_KEYS_DIR need to be updated whenever reading them.
def set_keys_dir(name, d):
    if (d.getVar(name, True) != "1") or (d.getVar('SIGNING_MODEL', True) != "user"):
        return

    if d.getVar(name + '_KEYS_DIR', True) == d.getVar('SAMPLE_' + name + '_KEYS_DIR', True):
        d.setVar(name + '_KEYS_DIR', d.getVar('DEPLOY_DIR_IMAGE', True) + '/user-keys/' + name.lower() + '_keys')

python check_deploy_keys() {
    # XXX: the user key for rpm signing is necessary but not required.
    for _ in ('UEFI_SB', 'MOK_SB', 'IMA', 'SYSTEM_TRUSTED'):
        if d.getVar(_, True) != "1":
            continue

        # Intend to use user key?
        if not d.getVar('SIGNING_MODEL', True) in ("sample", "user"):
            continue

        # Raise error if not specifying the location of the
        # user keys.
        sanity_check_user_keys(_, True, d)

        deploy_keys(_, d)
}

check_deploy_keys[lockfiles] = "${TMPDIR}/check_deploy_keys.lock"
