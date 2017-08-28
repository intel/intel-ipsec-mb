# Copyright (c) 2017, Intel Corporation
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
%global githubver    0.46
%global githubfull   %{githubname}-v%{githubver}

# disable producing debuginfo for this package
%global debug_package %{nil}

Summary:            IPSEC cryptography library optimized for Intel Architecture
Name:               %{githubname}
Release:            1%{?dist}
Version:            %{githubver}
License:            BSD
Group:              Development/Tools
ExclusiveArch:      x86_64
Source0:            https://github.com/01org/%{githubname}/archive/%{githubname}-v%{githubver}.tar.gz
URL:                https://github.com/01org/%{githubname}

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
https://github.com/01org/%{githubname}

%prep
%setup -n %{githubfull}

%build
make %{?_smp_mflags}

%install
install -d %{buildroot}/%{_licensedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/LICENSE %{buildroot}/%{_licensedir}/%{name}-%{version}

# Install the library
install -d %{buildroot}/%{_libdir}
install -m 0644 -s %{_builddir}/%{githubfull}/libIPSec_MB.a %{buildroot}/%{_libdir}

# Install the header file
install -d %{buildroot}/%{_includedir}
install -d %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/include/types.h %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/constants.h %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/job_aes_hmac.h %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/asm_types.h %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/mb_mgr.h %{buildroot}/%{_includedir}/%{name}-%{version}
install -m 0644 %{_builddir}/%{githubfull}/gcm_defines.h %{buildroot}/%{_includedir}/%{name}-%{version}

%files

%{!?_licensedir:%global license %%doc}
%license %{_licensedir}/%{name}-%{version}/LICENSE
%doc README ReleaseNotes.txt

%files -n intel-ipsec-mb-devel
%{_includedir}/%{name}-%{version}/types.h
%{_includedir}/%{name}-%{version}/constants.h
%{_includedir}/%{name}-%{version}/job_aes_hmac.h
%{_includedir}/%{name}-%{version}/asm_types.h
%{_includedir}/%{name}-%{version}/gcm_defines.h
%{_includedir}/%{name}-%{version}/mb_mgr.h
%{_libdir}/libIPSec_MB.a

%changelog
* Fri Aug 11 2017 Tomasz Kantecki <tomasz.kantecki@intel.com> 0.46-1
- initial version of the package
