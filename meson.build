project('tlmi-auth', 'c',
    version : '1.0.1',
    license : 'GPL-2.0-or-later',
    default_options : [
        'buildtype=debugoptimized',
        'b_asneeded=True',
        'b_lundef=True',
        'b_pie=true',
        'c_std=gnu11',
        'warning_level=3',
    ],
    meson_version : '>=0.54.0')

add_project_arguments(
    '-DTLMI_PROG_VER="@0@"'.format(meson.project_version()),
    language : 'c',
)

openssl_minver = '1.1.0'
libcrypto_dep = dependency('libcrypto', version : '>=@0@'.format(openssl_minver))
libssl_dep = dependency('libssl', version : '>=@0@'.format(openssl_minver))

if libcrypto_dep.version() >= '3.0.0'
    add_project_arguments('-DOPENSSL_API_COMPAT=0x1010000L', language : 'c')
endif

tlmi_auth_src = files(
    'src/tlmi_crypto.c',
    'src/tlmi_auth.c',
)

tlmi_auth = executable('tlmi-auth',
    tlmi_auth_src,
    dependencies : [libcrypto_dep, libssl_dep],
    install : true,
)
