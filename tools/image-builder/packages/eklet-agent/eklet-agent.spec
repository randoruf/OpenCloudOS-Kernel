%global goproject https://git.woa.com/tke/eks
%global gorepo eklet-agent
%global goimport %{goproject}/%{gorepo}

%global gover 2.8.12.dirty1
%global rpmver %{gover}

Name: eklet-agent
Version: %{rpmver}
Release: 1%{?dist}
Summary: eklet agent
License: Apache-2.0
URL: https://git.woa.com/tke/eks/eklet-agent
Source1: eklet-agent-init.service
Source2: eklet-agent.service
Source3: eklet-agent-final.service
Source4: final.sh

BuildRequires: glibc-devel
Requires: runc
Requires: systemd
Requires: containerd

%description
%{summary}.

%prep
%global install_dir /opt/eklet-agent
mkdir eklet-agent-%{version}
cd eklet-agent-%{version}
git clone --recurse-submodules  -b disable-9100 ssh://git@git.woa.com:22/tke/eks/eklet-agent.git .
git checkout v%{version}
go env -w GOPROXY="https://goproxy.woa.com,direct" 
go env -w GOSUMDB="sum.woa.com+643d7a06+Ac5f5VOC4N8NUXdmhbm8pZSXIWfhek5JSmWdWrq7pLX4"
go env -w GOPRIVATE=""
go mod vendor

%build
cd eklet-agent-%{version}
%set_cross_go_flags
make build
%{_cross_compile}strip target/eklet-agent
%{_cross_compile}strip target/eklet-agent-init

%install
cd eklet-agent-%{version}
install -d %{buildroot}%{_cross_unitdir}
install -p -m 0644 %{S:1} %{S:2} %{S:3} %{buildroot}%{_cross_unitdir}/
install -d %{buildroot}%{install_dir}
install -p -m 0755 target/eklet-agent %{buildroot}%{install_dir}
install -p -m 0755 target/eklet-agent-init %{buildroot}%{install_dir}
install -p -m 0755 %{S:4} %{buildroot}%{install_dir}
mkdir -p %{buildroot}%{_cross_unitdir}/multi-user.target.wants
ln -sf %{_cross_unitdir}/eklet-agent.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent.service
ln -sf %{_cross_unitdir}/eklet-agent-init.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-init.service
ln -sf %{_cross_unitdir}/eklet-agent-final.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-final.service

%files
%dir %{install_dir}
%{install_dir}/eklet-agent
%{install_dir}/eklet-agent-init
%{install_dir}/final.sh
%{_cross_unitdir}/*
%dir %{_cross_unitdir}/multi-user.target.wants
%{_cross_unitdir}/multi-user.target.wants/*
