Name: eks-tool
Version: 1.0.0
Release: 1%{?dist}
Summary: eks tool
License: Apache-2.0
Source1: crictl

%description
%{summary}.

%prep

%build

%install
install -d %{buildroot}%{_cross_sbindir}
install -p -m 0755 %{S:1} %{buildroot}%{_cross_sbindir}

%files
%{_cross_sbindir}/crictl

%changelog
