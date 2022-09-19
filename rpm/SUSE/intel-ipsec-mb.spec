#
# spec file for package intel-ipsec-mb
#
# Copyright (c) 2022 SUSE LLC
# Copyright (c) 2022, Intel Corporation
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#

# Versions numbers
%global major        1
%global minor        3
%global patch        0

# GitHub properties
%global githubver    %{major}.%{minor}
%global githubfull   %{name}-%{githubver}

%global rpm_name     libIPSec_MB

Name:               intel-ipsec-mb
Summary:            IPSec cryptography library optimized for Intel Architecture
Release:            0
Version:            %{major}.%{minor}.%{patch}
License:            BSD-3-Clause
Group:              Development/Libraries/C and C++
URL:                https://github.com/intel/%{name}
Source0:            https://github.com/intel/%{name}/archive/v%{githubver}.tar.gz#/%{githubfull}.tar.gz
ExclusiveArch:      x86_64
BuildRequires:      make
BuildRequires:      gcc >= 4.8.3
BuildRequires:      nasm >= 2.14

%description
An IPSec cryptography library optimized for Intel Architecture
and primarily targeted at packet processing applications.

%package devel
Summary:            Headers for the Intel IPSec cryptographic library
Requires:           %{rpm_name}%{major}%{?_isa} = %{version}-%{release}
Group:              Development/Libraries/C and C++

%description devel
An IPSec cryptography library optimized for Intel Architecture
and primarily targeted at packet processing applications.

This package contains the headers for building programs with the library.

%package -n %{rpm_name}%{major}
Summary:            IPSec cryptography library optimized for Intel Architecture
Group:              System/Libraries

%description -n %{rpm_name}%{major}
An IPSec cryptography library optimized for Intel Architecture
and primarily targeted at packet processing applications.

%prep
%autosetup -n %{name}-%{githubver}

%build
cd lib
%make_build EXTRA_CFLAGS='%{optflags}'

%install
install -d %{buildroot}/%{_includedir}
install -m 0644 %{_builddir}/%{githubfull}/lib/intel-ipsec-mb.h %{buildroot}/%{_includedir}
install -d %{buildroot}/%{_libdir}
install -s -m 0755 %{_builddir}/%{githubfull}/lib/libIPSec_MB.so.%{version} %{buildroot}/%{_libdir}
install -d %{buildroot}/%{_mandir}/man7
install -m 0444 lib/libipsec-mb.7 %{buildroot}/%{_mandir}/man7
install -m 0444 lib/libipsec-mb-dev.7 %{buildroot}/%{_mandir}/man7
cd %{buildroot}/%{_libdir}
ln -s libIPSec_MB.so.%{version} libIPSec_MB.so.%{major}
ln -s libIPSec_MB.so.%{version} libIPSec_MB.so

%files -n %{rpm_name}%{major}
%license LICENSE
%{_libdir}/libIPSec_MB.so.%{version}
%{_libdir}/libIPSec_MB.so.%{major}

%files devel
%doc README ReleaseNotes.txt
%{_includedir}/intel-ipsec-mb.h
%{_mandir}/man7/libipsec-mb.7.gz
%{_mandir}/man7/libipsec-mb-dev.7.gz
%{_libdir}/libIPSec_MB.so

%post  -n %{rpm_name}%{major} -p /sbin/ldconfig
%postun -n %{rpm_name}%{major} -p /sbin/ldconfig

%changelog
