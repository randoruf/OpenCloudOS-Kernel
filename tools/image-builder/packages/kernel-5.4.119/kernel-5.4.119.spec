%global debug_package %{nil}

Name: kernel
Version: 5.4.119
Release: 19%{?dist}
Summary: The Linux kernel
License: GPL-2.0 WITH Linux-syscall-note
Source100: kernel_config

BuildRequires: bc
BuildRequires: elfutils-devel
BuildRequires: hostname
BuildRequires: kmod
BuildRequires: openssl-devel

%global kernel_sourcedir %{_cross_usrsrc}/kernels
%global kernel_libdir %{_cross_libdir}/modules/%{version}

%description
%{summary}.

%package devel
Summary: Configured Linux kernel source for module building
Requires: filesystem

%description devel
%{summary}.

%package modules
Summary: Modules for the Linux kernel

%description modules
%{summary}.

%package headers
Summary: Header files for the Linux kernel for use by glibc

%description headers
%{summary}.

%prep
if [ %{_cross_arch} == "aarch64" ];then
    git clone -b arm64-5.4.119-19-0009 https://github.com/Tencent/TencentOS-kernel.git ./tencentos-%{version}
else
    git clone -b x86-5.4.119-19-0010.prerelease9 https://github.com/Tencent/TencentOS-kernel.git ./tencentos-%{version}
fi

%setup -TDn tencentos-%{version}
%autopatch -p1
if [ %{_cross_arch} == "aarch64" ];then
    cp arch/%{_cross_karch}/configs/defconfig ../config-%{_cross_arch}
else
    cp arch/%{_cross_karch}/configs/%{_cross_arch}_defconfig ../config-%{_cross_arch}
fi

KCONFIG_CONFIG="arch/%{_cross_karch}/configs/%{_cross_vendor}_defconfig" \
    ARCH="%{_cross_karch}" \
    scripts/kconfig/merge_config.sh ../config-%{_cross_arch} %{SOURCE100}
rm -f ../config-%{_cross_arch} ../*.patch

%global kmake \
make -s\\\
  ARCH="%{_cross_karch}"\\\
  CROSS_COMPILE="%{_cross_compile}"\\\
  INSTALL_HDR_PATH="%{buildroot}%{_cross_prefix}"\\\
  INSTALL_MOD_PATH="%{buildroot}%{_cross_prefix}"\\\
  INSTALL_MOD_STRIP=1\\\
%{nil}

%build
%kmake mrproper
%kmake %{_cross_vendor}_defconfig
%kmake %{?_smp_mflags} %{_cross_kimage}
%kmake %{?_smp_mflags} modules

%install
%kmake headers_install
%kmake modules_install

install -d %{buildroot}/boot
install -T -m 0755 arch/%{_cross_karch}/boot/%{_cross_kimage} %{buildroot}/boot/vmlinuz
install -m 0644 .config %{buildroot}/boot/config
install -m 0644 System.map %{buildroot}/boot/System.map

find %{buildroot}%{_cross_prefix} \
   \( -name .install -o -name .check -o \
      -name ..install.cmd -o -name ..check.cmd \) -delete

# For out-of-tree kmod builds, we need to support the following targets:
#   make scripts -> make prepare -> make modules
#
# This requires enough of the kernel tree to build host programs under the
# "scripts" and "tools" directories.

# Any existing ELF objects will not work properly if we're cross-compiling for
# a different architecture, so get rid of them to avoid confusing errors.
find arch scripts tools -type f -executable \
  -exec sh -c "head -c4 {} | grep -q ELF && rm {}" \;

# We don't need to include these files.
find -type f \( -name \*.cmd -o -name \*.gitignore \) -delete

# Avoid an OpenSSL dependency by stubbing out options for module signing and
# trusted keyrings, so `sign-file` and `extract-cert` won't be built. External
# kernel modules do not have access to the keys they would need to make use of
# these tools.
sed -i \
  -e 's,$(CONFIG_MODULE_SIG_FORMAT),n,g' \
  -e 's,$(CONFIG_SYSTEM_TRUSTED_KEYRING),n,g' \
  scripts/Makefile

(
  find * \
    -type f \
    \( -name Build\* -o -name Kbuild\* -o -name Kconfig\* -o -name Makefile\* \) \
    -print

  find arch/%{_cross_karch}/ \
    -type f \
    \( -name module.lds -o -name vmlinux.lds.S -o -name Platform -o -name \*.tbl \) \
    -print

  find arch/%{_cross_karch}/{include,lib}/ -type f ! -name \*.o ! -name \*.o.d -print
  echo arch/%{_cross_karch}/kernel/asm-offsets.s
  echo lib/vdso/gettimeofday.c

  for d in \
    arch/%{_cross_karch}/tools \
    arch/%{_cross_karch}/kernel/vdso ; do
    [ -d "${d}" ] && find "${d}/" -type f -print
  done

  find include -type f -print
  find scripts -type f ! -name \*.l ! -name \*.y ! -name \*.o -print

  find tools/{arch/%{_cross_karch},include,objtool,scripts}/ -type f ! -name \*.o -print
  echo tools/build/fixdep.c
  find tools/lib/subcmd -type f -print
  find tools/lib/{ctype,string,str_error_r}.c

  echo kernel/bounds.c
  echo kernel/time/timeconst.bc
  echo security/selinux/include/classmap.h
  echo security/selinux/include/initial_sid_to_string.h

  echo .config
  echo Module.symvers
  echo System.map
) | sort -u > kernel_devel_files

mkdir -p %{buildroot}%{kernel_sourcedir}/%{version}
mkdir -p %{buildroot}%{_usrsrc}/kernels
mkdir -p %{buildroot}%{kernel_libdir}

tar c -T kernel_devel_files | tar x -C %{buildroot}%{kernel_sourcedir}/%{version}
rm -f %{buildroot}%{kernel_libdir}/build %{buildroot}%{kernel_libdir}/source
ln -sf %{_usrsrc}/kernels/%{version} %{buildroot}%{kernel_libdir}/build
ln -sf %{_usrsrc}/kernels/%{version} %{buildroot}%{kernel_libdir}/source
%files
%license COPYING LICENSES/preferred/GPL-2.0 LICENSES/exceptions/Linux-syscall-note
/boot/vmlinuz
/boot/config
/boot/System.map

%files modules
%dir %{_cross_libdir}/modules
%{_cross_libdir}/modules/*

%files headers
%dir %{_cross_includedir}/asm
%dir %{_cross_includedir}/asm-generic
%dir %{_cross_includedir}/drm
%dir %{_cross_includedir}/linux
%dir %{_cross_includedir}/misc
%dir %{_cross_includedir}/mtd
%dir %{_cross_includedir}/rdma
%dir %{_cross_includedir}/scsi
%dir %{_cross_includedir}/sound
%dir %{_cross_includedir}/video
%dir %{_cross_includedir}/xen
%{_cross_includedir}/asm/*
%{_cross_includedir}/asm-generic/*
%{_cross_includedir}/drm/*
%{_cross_includedir}/linux/*
%{_cross_includedir}/misc/*
%{_cross_includedir}/mtd/*
%{_cross_includedir}/rdma/*
%{_cross_includedir}/scsi/*
%{_cross_includedir}/sound/*
%{_cross_includedir}/video/*
%{_cross_includedir}/xen/*

%files devel
%dir %{kernel_sourcedir}
%{kernel_sourcedir}/%{version}/*
%{kernel_sourcedir}/%{version}/.config

%changelog
