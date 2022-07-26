%global debug_package %{nil}

Name: ebpf-tools
Version: 0.0.1
Release: 1
Summary: Tencent ebpf tools
License: Apache-2.0

BuildRequires: libcap-devel
BuildRequires: binutils-devel
BuildRequires: elfutils-libelf-devel
Requires: kernel

%description
%{summary}.

%prep
git clone git@git.woa.com:x-group/selfserver.git

%build
cd selfserver

# libbfd.so and libopcodes.so specify the use of static libraries, but the write dead
# path is /usr/lib64, so we need to create a link
ln -fs %{_cross_sysroot}/usr/lib64/libbfd.a /usr/lib64/libbfd.a
ln -fs %{_cross_sysroot}/usr/lib64/libopcodes.a /usr/lib64/libopcodes.a

make \
	CFLAGS+="-I%{_cross_sysroot}/usr/include" \
	LDFLAGS+="-L%{_cross_sysroot}/usr/lib64"

rm -rf %{_builddir}/selfserver/sysroot/bin/bootstrap
%{_cross_compile}strip %{_builddir}/selfserver/sysroot/bin/*
%{_cross_compile}strip %{_builddir}/selfserver/sysroot/lib/*

%install
install -d %{buildroot}/opt/eklet-agent
install -d %{buildroot}%{_cross_lib64dir}

install -p -m 0755 %{_builddir}/selfserver/sysroot/bin/* %{buildroot}/opt/eklet-agent
install -p -m 0755 %{_builddir}/selfserver/sysroot/lib/*.so* %{buildroot}%{_cross_lib64dir}

%files
/opt/eklet-agent/*
%{_cross_lib64dir}/*

%changelog
