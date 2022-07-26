%global project https://git.woa.com/imagedong
%global repo eks-network

Name: eklet-agent-net
Version: 1.0.0
Release: 1%{?dist}
Summary: eklet agent network
License: Apache-2.0
URL: https://%{project}/%{repo}
Source1: eklet-agent-config.service
Source2: eklet-agent-net.service
Source3: eklet-dns-cache.service
Source4: config-fun.sh
Source5: config-metadata.sh
Source6: config-network.sh

Requires: ebpf-tools

%description
%{summary}.

%prep
%global install_dir /opt/eklet-agent

%build

%install
install -d %{buildroot}%{_cross_unitdir}/multi-user.target.wants
install -p -m 0644 %{S:1} %{S:2} %{S:3} %{buildroot}%{_cross_unitdir}
ln -sf %{_cross_unitdir}/eklet-dns-cache.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-dns-cache.service
ln -sf %{_cross_unitdir}/eklet-agent-config.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-config.service
ln -sf %{_cross_unitdir}/eklet-agent-net.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-net.service
install -d %{buildroot}%{install_dir}
install -p -m 0755 %{S:4} %{S:5} %{S:6} %{buildroot}%{install_dir}
install -d %{buildroot}%{install_dir}/manifests
dd if=/dev/zero of=%{buildroot}%{install_dir}/reserved.file bs=128K count=10

%files
%dir %{install_dir}
%{install_dir}/*
%dir %{install_dir}/manifests
%{_cross_unitdir}/*
%dir %{_cross_unitdir}/multi-user.target.wants
%{_cross_unitdir}/multi-user.target.wants/*

%changelog
