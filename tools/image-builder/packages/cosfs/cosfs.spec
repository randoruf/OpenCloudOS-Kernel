%global debug_package %{nil}
%global _dwz_low_mem_die_limit 0

Name: cosfs
Version: 4.2.1
Release: 1
Summary: Mount Tencent COS bucket to local filesystem on Linux/Mac OS X
License: Apache-2.0

BuildRequires: glibc-devel
BuildRequires: libcurl-devel
BuildRequires: libxml2-devel
BuildRequires: fuse-devel
BuildRequires: openssl-devel
BuildRequires: fuse
Requires: nspr
Requires: libstdc++
Requires: fuse-libs
Requires: nss-softokn-freebl

%description
%{summary}.

%prep
git clone https://github.com/tencentyun/cosfs-v4.2.1
rm -rf cosfs-v4.2.1/configure
rm -rf cosfs-v4.2.1/aclocal.m4 cosfs-v4.2.1/autom4te.cache

%build
cd cosfs-v4.2.1
./autogen.sh
./configure CFLAGS="--sysroot=%{_cross_sysroot}" CXXFLAGS="--sysroot=%{_cross_sysroot}" LDFLAGS="--sysroot=%{_cross_sysroot}"
make -j$(nproc) 

%install
install -d %{buildroot}%{_cross_sbindir}
install -p -m 0755 %{_builddir}/cosfs-v4.2.1/src/cosfs %{buildroot}%{_cross_sbindir}

%files
%{_cross_sbindir}/cosfs

%changelog
