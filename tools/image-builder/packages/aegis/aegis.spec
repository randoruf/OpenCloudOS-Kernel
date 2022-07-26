%global debug_package %{nil}
%global aegis_source "$(pwd)"
%global kernel_version "5.4.87"
%global modules_path "%{kernel_version}-1"

Name: aegis
Release: 1
Version: 0.0.1
Summary: aegis driver for Linux
Url: http://download.nvidia.com/XFree86
License: Software License

BuildRequires: kernel-devel
Requires: kernel

%description
%{summary}.

%prep
# git clone aegis
git clone -b aegis_modules git@git.woa.com:tlinux/tools_misc.git

%build
%global modules_dir "%{aegis_source}/tools_misc"
%global linux_dir "%{_cross_sysroot}/usr/src/kernels/%{kernel_version}"

make -C %{linux_dir} prepare

# make modules
make -C %{linux_dir} \
  CROSS_COMPILE="%{_cross_compile}" \
  M="%{modules_dir}" modules V=1 \
%{nil}

# strip modules
%{_cross_compile}strip --strip-unneeded \
  --remove-section=.pdr \
  --remove-section=.comment \
  --remove-section=.mdebug.abi32 \
  %{modules_dir}/*.ko

%install
%global k_suffix "$(awk -F'"|=' '/CONFIG_LOCALVERSION=/{print $3}' %{linux_dir}/.config)"

install -d %{buildroot}%{_cross_libdir}/modules/%{modules_path}%{k_suffix}/extra/
install -p -m 0755 %{modules_dir}/*.ko %{buildroot}%{_cross_libdir}/modules/%{modules_path}%{k_suffix}/extra/

%files
%{_cross_libdir}/modules/*

%changelog
