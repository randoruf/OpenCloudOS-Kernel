%global debug_package %{nil}

%global goproject github.com/opencontainers
%global gorepo runc
%global goimport %{goproject}/%{gorepo}
%global commit 12644e614e25b05da6fd08a38ffa0cfe1903fdec
%global shortcommit 12644e6

%global gover 1.0.0-rc93
%global rpmver 1.0.0~rc93

%global _dwz_low_mem_die_limit 0

Name: %{gorepo}
Version: %{rpmver}
Release: 1.%{shortcommit}%{?dist}
Summary: CLI for running Open Containers
License: Apache-2.0
Source0:https://%{goimport}/archive/%{commit}/%{gorepo}-%{commit}.tar.gz

BuildRequires: glibc-devel
BuildRequires: libseccomp-devel
Requires: libseccomp

%description
%{summary}.

%prep
wget https://%{goimport}/archive/%{commit}/%{gorepo}-%{commit}.tar.gz
tar -xvf %{gorepo}-%{commit}.tar.gz;
cp %{gorepo}-%{commit}.tar.gz %{_sourcedir}
%cross_go_setup %{gorepo}-%{commit} %{goproject} %{goimport}

%build
%cross_go_configure %{goimport}
export LD_VERSION="-X main.version=%{gover}+eks"
export LD_COMMIT="-X main.gitCommit=%{commit}"
go build \
  -trimpath "-buildmode=pie" \
  -ldflags="-linkmode=external ${LD_VERSION} ${LD_COMMIT}" \
  -o %{_builddir}/bin/runc .

%install
install -d %{buildroot}%{_cross_sbindir}
install -p -m 0755 %{_builddir}/bin/runc %{buildroot}%{_cross_sbindir}

%files
%{_cross_sbindir}/runc

%changelog
