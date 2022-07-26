%global debug_package %{nil}
%global kernel_version "5.4.119"
%global gpu_source "$(pwd)/gpu_src"
%global modules_path "%{kernel_version}-1"

Name: nvidia
Release: 1
Version: 460.32.03
Summary: nvidia gpu driver for Linux
Url: http://download.nvidia.com/XFree86
License: NVIDIA Software License
Source100: gl.pc
Source200: egl.pc

Requires: glibc
Requires: nvidia-cuda
Requires: nvidia-libs
Requires: nvidia-devel
Requires: nvidia-opencl
Requires: nvidia-driver

%description
%{summary}.

%package driver
Summary: Linux nvidia driver modules 
BuildRequires: kernel-devel

%description driver 
%{summary}.

%package libs
Summary: Linux nvidia library for x drivers.

%description libs
%{summary}.

%package devel
Summary: Linux nvidia private library.
Requires: nvidia-libs

%description devel
%{summary}.

%package cuda-libs
Summary: Linux nvidia CUDA library.

%description cuda-libs 
%{summary}.

%package cuda
Summary: Linux nvidia CUDA progs.
Requires: nvidia-cuda-libs

%description cuda
%{summary}.

%package opencl
Summary: Linux nvidia openCL library.

%description opencl
%{summary}.

%package opengl
Summary: Linux nvidia openGL library.

%description opengl
%{summary}.

%package setting
Summary: Linux nvidia setting.

%description setting
%{summary}.

%prep
# download nvidia install file
wget %{url}/Linux-%{_cross_arch}/%{version}/NVIDIA-Linux-%{_cross_arch}-%{version}.run
sh ./NVIDIA-Linux-%{_cross_arch}-%{version}.run --extract-only --target %{gpu_source}

%build
%global modules_dir "%{gpu_source}/kernel"
%global kernel_modules "nvidia nvidia-modeset nvidia-drm nvidia-uvm"
%global linux_dir "%{_cross_sysroot}/usr/src/kernels/%{kernel_version}"

make -C %{linux_dir} prepare

# make modules
make -C %{linux_dir} \
  NV_SPECTRE_V2=0    \
  NV_KERNEL_OUTPUT="%{linux_dir}" \
  NV_KERNEL_SOURCES="%{linux_dir}" \
  NV_KERNEL_MODULES=""%{kernel_modules}"" \
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

install -d %{buildroot}%{_cross_bindir}
install -d %{buildroot}%{_cross_lib64dir}
install -d %{buildroot}%{_cross_pkgconfigdir}
install -d %{buildroot}%{_cross_libdir}/modules/%{modules_path}%{k_suffix}/extra/

install -p -m 0755 %{S:100} %{buildroot}%{_cross_pkgconfigdir}
install -p -m 0755 %{S:200} %{buildroot}%{_cross_pkgconfigdir}
install -p -m 0755 %{gpu_source}/*.so* %{buildroot}%{_cross_lib64dir}
install -p -m 0755 %{gpu_source}/nvidia-smi %{buildroot}%{_cross_bindir}
install -p -m 0755 %{gpu_source}/nvidia-modprobe %{buildroot}%{_cross_bindir}
install -p -m 0755 %{gpu_source}/nvidia-cuda-mps-server %{buildroot}%{_cross_bindir}
install -p -m 0755 %{gpu_source}/nvidia-cuda-mps-control %{buildroot}%{_cross_bindir}
install -p -m 0755 %{modules_dir}/*.ko %{buildroot}%{_cross_libdir}/modules/%{modules_path}%{k_suffix}/extra/

%files
%dir %{_cross_pkgconfigdir}
%{_cross_pkgconfigdir}/gl.pc
%{_cross_pkgconfigdir}/egl.pc

%files driver
%{_cross_libdir}/modules/*

%files libs
%{_cross_lib64dir}/libGLX.so.0
%{_cross_lib64dir}/libGL.so.1.7.0
%{_cross_lib64dir}/libEGL.so.1.1.0
%{_cross_lib64dir}/libGLdispatch.so.0
%{_cross_lib64dir}/libGLESv2.so.2.1.0
%{_cross_lib64dir}/libGLESv1_CM.so.1.2.0
%{_cross_lib64dir}/libnvidia-egl-wayland.so.1.1.5
%{_cross_lib64dir}/libEGL.so.%{version}
%{_cross_lib64dir}/libnvoptix.so.%{version}
%{_cross_lib64dir}/libGLX_nvidia.so.%{version}
%{_cross_lib64dir}/libEGL_nvidia.so.%{version}
%{_cross_lib64dir}/libnvidia-tls.so.%{version}
%{_cross_lib64dir}/libnvidia-ngx.so.%{version}
%{_cross_lib64dir}/libnvidia-glsi.so.%{version}
%{_cross_lib64dir}/libvdpau_nvidia.so.%{version}
%{_cross_lib64dir}/libnvidia-glcore.so.%{version}
%{_cross_lib64dir}/libGLESv2_nvidia.so.%{version}
%{_cross_lib64dir}/libnvidia-eglcore.so.%{version}
%{_cross_lib64dir}/libGLESv1_CM_nvidia.so.%{version}
%{_cross_lib64dir}/libnvidia-glvkspirv.so.%{version}
%{_cross_lib64dir}/libnvidia-opticalflow.so.%{version}
%{_cross_lib64dir}/nvidia_drv.so
%{_cross_lib64dir}/libglxserver_nvidia.so.%{version}
#%{_cross_lib64dir}/libGLX.so.0
#%{_cross_lib64dir}/libGLX_nvidia.so.%{version}

%files devel
%{_cross_lib64dir}/libnvidia-ifr.so.%{version}
%{_cross_lib64dir}/libnvidia-fbc.so.%{version}

%files cuda-libs
%{_cross_lib64dir}/libcuda.so.%{version}
%{_cross_lib64dir}/libnvcuvid.so.%{version}
%{_cross_lib64dir}/libnvidia-ml.so.%{version}
%{_cross_lib64dir}/libnvidia-cbl.so.%{version}
%{_cross_lib64dir}/libnvidia-cfg.so.%{version}
%{_cross_lib64dir}/libnvidia-encode.so.%{version}
%{_cross_lib64dir}/libnvidia-rtcore.so.%{version}
%{_cross_lib64dir}/libnvidia-compiler.so.%{version}
%{_cross_lib64dir}/libnvidia-allocator.so.%{version}
%{_cross_lib64dir}/libnvidia-ptxjitcompiler.so.%{version}

%files cuda
%{_cross_bindir}/nvidia-smi
%{_cross_bindir}/nvidia-modprobe
%{_cross_bindir}/nvidia-cuda-mps-server
%{_cross_bindir}/nvidia-cuda-mps-control

%files opencl
%{_cross_lib64dir}/libOpenCL.so.1.0.0
%{_cross_lib64dir}/libnvidia-opencl.so.%{version}

%files opengl
%{_cross_lib64dir}/libOpenGL.so.0

%files setting
%{_cross_lib64dir}/libnvidia-gtk2.so.%{version}
%{_cross_lib64dir}/libnvidia-gtk3.so.%{version}

%changelog
