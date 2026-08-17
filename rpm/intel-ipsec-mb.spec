# Copyright (c) 2017-2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause

# Versions numbers
%global major        2
%global minor        0
%global patch        0
%global fullversion  %{major}.%{minor}.%{patch}

# GitHub properties
%global githubname   intel-ipsec-mb
%global githubver    %{major}.%{minor}
%global githubfull   %{githubname}-%{githubver}

# disable producing debuginfo for this package
%global debug_package %{nil}

Summary:            IPSEC cryptography library optimized for Intel Architecture
Name:               %{githubname}
Release:            1%{?dist}
Version:            %{fullversion}
License:            BSD-3-Clause AND Apache-2.0
Group:              Development/Tools
ExclusiveArch:      x86_64
Source0:            https://github.com/intel/%{githubname}/archive/v%{githubver}.tar.gz#/%{githubfull}.tar.gz
URL:                https://github.com/intel/%{githubname}
BuildRequires:      cmake
BuildRequires:      make
BuildRequires:      gcc >= 4.8.3
BuildRequires:      nasm >= 2.14

%description
IPSEC cryptography library optimized for Intel Architecture

%package -n intel-ipsec-mb-devel
Summary:            IPSEC cryptography library optimized for Intel Architecture
License:            BSD-3-Clause
Requires:           %{name}%{?_isa} = %{version}-%{release}
Group:              Development/Tools
ExclusiveArch:      x86_64

%description -n intel-ipsec-mb-devel
IPSEC cryptography library optimized for Intel Architecture

For additional information please refer to:
https://github.com/intel/%{githubname}

%prep
%autosetup -n %{githubfull}

%if 0%{?rhel} && 0%{?rhel} < 8
%ldconfig_post

%ldconfig_postun
%endif

%build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBRARY_ONLY=ON \
      -DCMAKE_C_FLAGS_RELEASE="%{optflags}"
cmake --build build --parallel

%install

# Install the library
install -d %{buildroot}/%{_includedir}
install -m 0644 %{_builddir}/%{githubfull}/lib/intel-ipsec-mb.h %{buildroot}/%{_includedir}
install -d %{buildroot}/%{_libdir}
install -s -m 0755 %{_builddir}/%{githubfull}/build/lib/libIPSec_MB.so.%{fullversion} %{buildroot}/%{_libdir}
install -d %{buildroot}/%{_mandir}/man7
install -m 0444 lib/libipsec-mb.7 %{buildroot}/%{_mandir}/man7
install -m 0444 lib/libipsec-mb-dev.7 %{buildroot}/%{_mandir}/man7
cd %{buildroot}/%{_libdir}
ln -s libIPSec_MB.so.%{fullversion} libIPSec_MB.so.%{major}
ln -s libIPSec_MB.so.%{fullversion} libIPSec_MB.so

%files

%license LICENSE LICENSE.OpenSSL
%doc README ReleaseNotes.txt

%{_libdir}/libIPSec_MB.so.%{fullversion}
%{_libdir}/libIPSec_MB.so.%{major}

%{_mandir}/man7/libipsec-mb.7.gz

%files -n %{name}-devel
%{_includedir}/intel-ipsec-mb.h
%{_mandir}/man7/libipsec-mb-dev.7.gz
%{_libdir}/libIPSec_MB.so

%changelog
* Tue Nov 29 2024 Pablo de Lara Guarch <pablo.de.lara.guarch@intel.com> 2.0.0-1
- Update for release package v2.0

* Tue Jun 06 2023 Pablo de Lara Guarch <pablo.de.lara.guarch@intel.com> 1.4.0-1
- Update for release package v1.4

* Tue Sep 20 2022 Stephen Mcintyre <stephen.mcintyre@intel.com> 1.3.0-1
- Update for release package v1.3

* Fri Feb 11 2022 Stephen Mcintyre <stephen.mcintyre@intel.com> 1.2.0-1
- Update for release package v1.2

* Fri Oct 22 2021 Pablo de Lara Guarch <pablo.de.lara.guarch@intel.com> 1.1.0-1
- Update for release package v1.1

* Fri Apr 23 2021 Pablo de Lara Guarch <pablo.de.lara.guarch@intel.com> 1.0.0-1
- Update for release package v1.0

* Thu Oct 29 2020 Marcel Cornu <marcel.d.cornu@intel.com> 0.55.0-1
- Update for release package v0.55

* Tue Sep 08 2020 Marcel Cornu <marcel.d.cornu@intel.com> 0.54.0-2
- Updated to improve compliance with packaging guidelines
- Added patch to fix executable stack issue

* Thu May 14 2020 Marcel Cornu <marcel.d.cornu@intel.com> 0.54.0-1
- Update for release package v0.54.0

* Thu Sep 13 2018 Marcel Cornu <marcel.d.cornu@intel.com> 0.51-1
- Update for release package v0.51

* Mon Apr 16 2018 Tomasz Kantecki <tomasz.kantecki@intel.com> 0.49-1
- update for release package v0.49
- 01org replaced with intel in URL's
- use of new makefile 'install' target with some workarounds

* Fri Aug 11 2017 Tomasz Kantecki <tomasz.kantecki@intel.com> 0.46-1
- initial version of the package
