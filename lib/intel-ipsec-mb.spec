# Copyright (c) 2017-2020, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%global githubname   intel-ipsec-mb
%global githubver    0.53
%global githubfull   %{githubname}-%{githubver}
%global patchversion 0

# disable producing debuginfo for this package
%global debug_package %{nil}

Summary:            IPSEC cryptography library optimized for Intel Architecture
Name:               %{githubname}
Release:            1%{?dist}
Version:            %{githubver}.%{patchversion}
License:            BSD
Group:              Development/Tools
ExclusiveArch:      x86_64
Source0:            https://github.com/intel/%{githubname}/archive/v%{githubver}.tar.gz
URL:                https://github.com/intel/%{githubname}
BuildRequires:      gcc, make, nasm

%description
IPSEC cryptography library optimized for Intel Architecture

%package -n intel-ipsec-mb-devel
Summary:            IPSEC cryptography library optimized for Intel Architecture
License:            BSD
Requires:           intel-ipsec-mb == %{version}
Group:              Development/Tools
ExclusiveArch:      x86_64

%description -n intel-ipsec-mb-devel
IPSEC cryptography library optimized for Intel Architecture

For additional information please refer to:
https://github.com/intel/%{githubname}

%prep
%autosetup -n %{githubfull}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%build
make %{?_smp_mflags}

%install
install -d %{buildroot}/%{_licensedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/LICENSE %{buildroot}/%{_licensedir}/%{name}-%{version}

# Install the library
# - include directory not created in the 'install' target - workaround
install -d %{buildroot}/%{_includedir}
make install -C %{_builddir}/%{githubfull} PREFIX=%{_buildroot} HDR_DIR=%{buildroot}/%{_includedir} LIB_INSTALL_DIR=%{buildroot}/%{_libdir} MAN_DIR=%{buildroot}/%{_mandir}/man7 NOLDCONFIG=y
# - workaround for no strip option in the 'install target'
rm -f %{buildroot}/%{_libdir}/libIPSec_MB.so*
install -s -m 0755 %{_builddir}/%{githubfull}/libIPSec_MB.so.%{version} %{buildroot}/%{_libdir}
cd %{buildroot}/%{_libdir}
ln -s libIPSec_MB.so.%{version} libIPSec_MB.so.0
ln -s libIPSec_MB.so.%{version} libIPSec_MB.so

%files

%{!?_licensedir:%global license %%doc}
%license %{_licensedir}/%{name}-%{version}/LICENSE
%doc README ReleaseNotes.txt

%{_libdir}/libIPSec_MB.so.%{version}
%{_libdir}/libIPSec_MB.so.0
%{_libdir}/libIPSec_MB.so

%{_mandir}/man7/libipsec-mb.7.gz

%files -n intel-ipsec-mb-devel
%{_includedir}/intel-ipsec-mb.h
%{_mandir}/man7/libipsec-mb-dev.7.gz

%changelog
* Mon Nov 11 2019 Marcel Cornu <marcel.d.cornu@intel.com> 0.53.0-1
- Update for release package v0.53.0

* Thu Sep 13 2018 Marcel Cornu <marcel.d.cornu@intel.com> 0.51-1
- Update for release package v0.51

* Mon Apr 16 2018 Tomasz Kantecki <tomasz.kantecki@intel.com> 0.49-1
- update for release package v0.49
- 01org replaced with intel in URL's
- use of new makefile 'install' target with some workarounds
* Fri Aug 11 2017 Tomasz Kantecki <tomasz.kantecki@intel.com> 0.46-1
- initial version of the package
