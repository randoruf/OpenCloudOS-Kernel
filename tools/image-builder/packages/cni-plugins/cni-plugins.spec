%global debug_package %{nil}

%global goproject github.com/containernetworking
%global gorepo plugins
%global goimport %{goproject}/%{gorepo}

%global gover 0.9.1
%global rpmver %{gover}

%global _dwz_low_mem_die_limit 0

Name: cni-%{gorepo}
Version: %{rpmver}
Release: 1%{?dist}
Summary: Plugins for container networking
License: Apache-2.0
URL: https://%{goimport}

BuildRequires: glibc-devel
Requires: iptables

%description
%{summary}.

%prep
%global install_dir /opt/cni/bin
wget https://%{goproject}/%{gorepo}/archive/v%{gover}/%{gorepo}-%{gover}.tar.gz
tar -xvf %{gorepo}-%{gover}.tar.gz
%cross_go_setup %{gorepo}-%{gover} %{goproject} %{goimport}

%build
%cross_go_configure %{goimport}
bash build_linux.sh

%install
cd %{gorepo}-%{gover}
install -d %{buildroot}%{install_dir}
install -p -m 0755 bin/ipvlan %{buildroot}%{install_dir}
install -p -m 0755 bin/static %{buildroot}%{install_dir}
install -p -m 0755 bin/loopback %{buildroot}%{install_dir}

%files
%dir %{install_dir}
%{install_dir}/*

%changelog
