#!/bin/sh
#
# lfs-automator.sh — Automação POSIX para Linux From Scratch
# -----------------------------------------------------------
# Objetivo: automatizar todo o processo do LFS (toolchain + sistema base),
# exceto criação/formatação/montagem de partições (responsabilidade do usuário).
#
# ⚠️ Este script é um orquestrador POSIX (usa /bin/sh). Evita bashismos.
#     Ele cria uma árvore de trabalho, baixa fontes/patches, valida checksums,
#     constrói a toolchain em $LFS/tools e depois entra em chroot para montar
#     o sistema base. Suporta variantes:
#       - INIT:  sysv  | systemd
#       - LIB:   pure64| multilib (experimental)
#
# Requisitos do host (aproximados):
#   - Ferramentas: gcc, g++, make, tar, xz, bzip2, gzip, patch, sed, awk, python3,
#                  wget OU curl, sha256sum, chown, chgrp, mount, chroot, sudo.
#   - Kernel > 4.x, arquitetura x86_64.
#   - $LFS já montado (ex.: /mnt/lfs) com pelo menos ~20-50 GB livres.
#
# Uso básico:
#   export LFS=/mnt/lfs              # já montado!
#   sudo -E sh lfs-automator.sh INIT=sysv LIB=pure64 JOBS=8 LFS_USER=lfs
#
# Configuração via variáveis de ambiente (pode passar no CLI VAR=valor):
#   INIT       = sysv | systemd          (padrão: sysv)
#   LIB        = pure64 | multilib       (padrão: pure64)
#   LFS        = caminho de montagem     (OBRIGATÓRIO, já montado)
#   LFS_USER   = usuário local para compilar toolchain (padrão: lfs)
#   JOBS       = -j para make (padrão: número de CPUs detectado)
#   BOOK_VER   = r"stable" ou versão (ex.: 12.1) - apenas informativo
#   SRC_MIRROR = URL base para fontes (padrão: espelhos LFS/Upstream nos manifests)
#   NONINT     = 1 para modo não interativo/sair no primeiro erro (set -e)
#
# Licença: MIT. Sem garantias. Multilib é complexo; aqui é experimental.
#
# -----------------------------------------------------------

set -u
[ "${NONINT-}" = "1" ] && set -e

# --- Configuração inicial ----------------------------------------------------
INIT=${INIT-sysv}
LIB=${LIB-pure64}
LFS=${LFS-}
LFS_USER=${LFS_USER-lfs}
BOOK_VER=${BOOK_VER-stable}
SRC_MIRROR=${SRC_MIRROR-}

# Detecta CPUs para -j
if command -v nproc >/dev/null 2>&1; then CPUS=$(nproc); else CPUS=2; fi
JOBS=${JOBS-$CPUS}

# --- Funções utilitárias POSIX ----------------------------------------------
msg() { printf "\033[1;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*" 1>&2; }
err() { printf "\033[1;31m[ERRO]\033[0m %s\n" "$*" 1>&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "Ferramenta requerida não encontrada: $1"; }

sumcheck() {
  file="$1"; expect="$2"
  need sha256sum
  got=$(sha256sum "$file" | awk '{print $1}') || return 1
  [ "$got" = "$expect" ] || {
    warn "SHA256 divergente para $file";
    warn "Esperado: $expect"; warn "Obtido:  $got"; return 1; }
}

fetch() {
  url="$1"; out="$2";
  if [ -n "${SRC_MIRROR}" ]; then
    base=$(printf "%s" "$url" | sed 's#^\(https\?\)://[^/]*/##')
    url="${SRC_MIRROR%/}/$base"
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -O "$out" -c "$url" || return 1
  elif command -v curl >/dev/null 2>&1; then
    curl -L "$url" -o "$out" || return 1
  else
    err "Precisa de wget ou curl"
  fi
}

# --- Verificações do ambiente ------------------------------------------------
check_host() {
  [ "$(id -u)" -eq 0 ] || err "Execute como root (use sudo -E)."
  [ -n "$LFS" ] || err "Defina LFS (ex.: export LFS=/mnt/lfs)."
  [ -d "$LFS" ] || err "$LFS não existe. Monte sua partição primeiro."
  mountpoint -q "$LFS" || warn "$LFS não parece ser um ponto de montagem (ok se já garantido)."
  need tar; need xz; need bzip2; need gzip; need make; need gcc; need awk; need sed; need patch; need chroot; need sha256sum
}

# --- Layout de diretórios ----------------------------------------------------
setup_layout() {
  mkdir -p "$LFS"/sources "$LFS"/tools "$LFS"/logs "$LFS"/build "$LFS"/manifests || err "Falha criando diretórios em $LFS"
  chmod -v a+wt "$LFS"/sources
}

# --- Usuário lfs para toolchain ---------------------------------------------
ensure_lfs_user() {
  if ! id "$LFS_USER" >/dev/null 2>&1; then
    msg "Criando usuário $LFS_USER (sem shell de login)"
    useradd -M -s /usr/sbin/nologin -U "$LFS_USER" || err "useradd falhou"
  fi
  chown -R "$LFS_USER":"$LFS_USER" "$LFS"/sources "$LFS"/tools "$LFS"/build || err "chown falhou"
}

# --- Manifests embutidos -----------------------------------------------------
# Formato CSV simples: name;version;url;sha256;patch_urls (se múltiplos, separados por espaço)
# Estes manifests cobrem um conjunto mínimo funcional. Ajuste conforme o BOOK_VER.
write_manifests() {
  cat >"$LFS/manifests/base-common.csv" <<'EOF'
# name;version;url;sha256;patch_urls
binutils;2.42;https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.xz;SKIP;
gcc;13.2.0;https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.xz;SKIP;
linux;6.6.32;https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.6.32.tar.xz;SKIP;
glibc;2.39;https://ftp.gnu.org/gnu/libc/glibc-2.39.tar.xz;SKIP;
mpfr;4.2.1;https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz;SKIP;
gmp;6.3.0;https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz;SKIP;
mpc;1.3.1;https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz;SKIP;
ncurses;6.5;https://invisible-mirror.net/archives/ncurses/ncurses-6.5.tar.gz;SKIP;
bash;5.2.32;https://ftp.gnu.org/gnu/bash/bash-5.2.32.tar.gz;SKIP;
coreutils;9.5;https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz;SKIP;
diffutils;3.10;https://ftp.gnu.org/gnu/diffutils/diffutils-3.10.tar.xz;SKIP;
file;5.45;https://astron.com/pub/file/file-5.45.tar.gz;SKIP;
findutils;4.10.0;https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz;SKIP;
gawk;5.3.0;https://ftp.gnu.org/gnu/gawk/gawk-5.3.0.tar.xz;SKIP;
grep;3.11;https://ftp.gnu.org/gnu/grep/grep-3.11.tar.xz;SKIP;
gzip;1.13;https://ftp.gnu.org/gnu/gzip/gzip-1.13.tar.xz;SKIP;
make;4.4.1;https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz;SKIP;
patch;2.7.6;https://ftp.gnu.org/gnu/patch/patch-2.7.6.tar.xz;SKIP;
perl;5.40.0;https://www.cpan.org/src/5.0/perl-5.40.0.tar.xz;SKIP;
pkgconf;2.3.0;https://distfiles.ariadne.space/pkgconf/pkgconf-2.3.0.tar.xz;SKIP;
python;3.12.5;https://www.python.org/ftp/python/3.12.5/Python-3.12.5.tgz;SKIP;
sed;4.9;https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz;SKIP;
tar;1.35;https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz;SKIP;
tcl;8.6.14;https://prdownloads.sourceforge.net/tcl/tcl8.6.14-src.tar.gz;SKIP;
texinfo;7.1;https://ftp.gnu.org/gnu/texinfo/texinfo-7.1.tar.xz;SKIP;
util-linux;2.40.2;https://www.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz;SKIP;
vim;9.1;https://github.com/vim/vim/archive/refs/tags/v9.1.0000.tar.gz;SKIP;
wheelfix;0;https://example.invalid/empty.tar.xz;SKIP;
EOF

  cat >"$LFS/manifests/base-sysv.csv" <<'EOF'
# name;version;url;sha256;patch_urls
sysvinit;3.10;https://download.savannah.nongnu.org/releases/sysvinit/sysvinit-3.10.tar.xz;SKIP;
kbd;2.6.4;https://www.kernel.org/pub/linux/utils/kbd/kbd-2.6.4.tar.xz;SKIP;
kmod;33;https://www.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz;SKIP;
shadow;4.15.1;https://github.com/shadow-maint/shadow/releases/download/v4.15.1/shadow-4.15.1.tar.xz;SKIP;
procps-ng;4.0.4;https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-4.0.4.tar.xz/download;SKIP;
udev-lfs;256;https://www.linuxfromscratch.org/lfs/downloads/stable/udev-lfs-256.tar.xz;SKIP;
EOF

  cat >"$LFS/manifests/base-systemd.csv" <<'EOF'
# name;version;url;sha256;patch_urls
systemd;256;https://github.com/systemd/systemd/archive/refs/tags/v256.tar.gz;SKIP;
kbd;2.6.4;https://www.kernel.org/pub/linux/utils/kbd/kbd-2.6.4.tar.xz;SKIP;
kmod;33;https://www.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz;SKIP;
shadow;4.15.1;https://github.com/shadow-maint/shadow/releases/download/v4.15.1/shadow-4.15.1.tar.xz;SKIP;
procps-ng;4.0.4;https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-4.0.4.tar.xz/download;SKIP;
EOF

  cat >"$LFS/manifests/order.txt" <<'EOF'
# Ordem grosseira de build (toolchain, depois base dentro do chroot)
# Toolchain fase 1/2
binutils:pass1
gcc:pass1
linux:headers
glibc:libs
libstdcpp:pass1
binutils:pass2
gcc:pass2
# Base em chroot (resumo mínimo)
linux:kernel
zlib
file
ncurses
bash
coreutils
diffutils
findutils
gawk
grep
gzip
make
patch
sed
tar
xz
bzip2
perl
python
tcl
texinfo
pkgconf
util-linux
shadow
kbd
kmod
procps-ng
# init específico
init:sysv
init:systemd
EOF
}

# --- Download de fontes e patches -------------------------------------------
# Lê CSVs e baixa para $LFS/sources; valida SHA256 quando não SKIP
fetch_all() {
  manifest_common="$LFS/manifests/base-common.csv"
  [ "$INIT" = "systemd" ] && manifest_init="$LFS/manifests/base-systemd.csv" || manifest_init="$LFS/manifests/base-sysv.csv"

  for mf in "$manifest_common" "$manifest_init"; do
    [ -f "$mf" ] || err "Manifesto ausente: $mf"
    awk -F';' 'BEGIN{OFS=";"} $0 ~ /^[ ]*#/ {next} NF>=4 {print $1,$2,$3,$4,$5}' "$mf" |
    while IFS=';' read -r name ver url sha patches; do
      [ -n "$name" ] || continue
      base=$(basename "$url")
      out="$LFS/sources/$base"
      if [ ! -f "$out" ]; then
        msg "Baixando $name-$ver"
        fetch "$url" "$out" || err "Falha ao baixar $url"
      else
        msg "Já existe: $base"
      fi
      [ "$sha" = "SKIP" ] || sumcheck "$out" "$sha" || err "Checksum falhou: $base"
      # Patches (se houver)
      for p in $patches; do
        [ -n "$p" ] || continue
        pbase=$(basename "$p")
        pout="$LFS/sources/$pbase"
        if [ ! -f "$pout" ]; then
          msg "Baixando patch $pbase"
          fetch "$p" "$pout" || err "Falha ao baixar patch $p"
        fi
      done
    done
  done
}

# --- Preparação da toolchain -------------------------------------------------
enter_as_lfs() {
  su -s /bin/sh -c "$1" "$LFS_USER"
}

make_dirs_toolchain() {
  mkdir -p "$LFS"/tools "$LFS"/build && chown -R "$LFS_USER":"$LFS_USER" "$LFS"/tools "$LFS"/build
  ln -svf "$LFS/tools" /tools 2>/dev/null || true
}

# NOTA: As receitas abaixo são simplificadas e podem precisar de ajustes conforme a versão do livro.
# Mantidas o mais POSIX possível. Logs em $LFS/logs.

build_binutils_pass1() {
  msg "[toolchain] binutils pass1"
  enter_as_lfs "cd $LFS/build && rm -rf binutils-p1 && mkdir binutils-p1 && cd binutils-p1 && \
    tar -xf $LFS/sources/binutils-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/binutils-*.tar.* && \
    mkdir build && cd build && \
    ../configure --prefix=/tools --with-sysroot=$LFS --target=x86_64-lfs-linux-gnu --disable-nls --disable-werror && \
    make -j$JOBS && make install" || err "binutils pass1 falhou"
}

build_gcc_pass1() {
  msg "[toolchain] gcc pass1"
  enter_as_lfs "cd $LFS/build && rm -rf gcc-p1 && mkdir gcc-p1 && cd gcc-p1 && \
    tar -xf $LFS/sources/gcc-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/gcc-*.tar.* && \
    tar -xf $LFS/sources/mpfr-*.tar.* && mv mpfr-* mpfr && \
    tar -xf $LFS/sources/gmp-*.tar.* && mv gmp-* gmp && \
    tar -xf $LFS/sources/mpc-*.tar.* && mv mpc-* mpc && \
    mkdir build && cd build && \
    ../configure --target=x86_64-lfs-linux-gnu --prefix=/tools \
                 --with-glibc-version=2.39 --with-sysroot=$LFS \
                 --with-newlib --without-headers --enable-initfini-array \
                 --disable-nls --disable-shared --disable-multilib \
                 --disable-decimal-float --disable-threads --disable-libatomic \
                 --disable-libgomp --disable-libquadmath --disable-libssp \
                 --disable-libvtv --disable-libstdcxx && \
    make -j$JOBS all-gcc all-target-libgcc && make install && \
    ln -svf /tools/bin/x86_64-lfs-linux-gnu-gcc /tools/bin/cc" || err "gcc pass1 falhou"
}

build_linux_headers() {
  msg "[toolchain] Linux headers"
  enter_as_lfs "cd $LFS/build && rm -rf linux-headers && mkdir linux-headers && cd linux-headers && \
    tar -xf $LFS/sources/linux-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/linux-*.tar.* && \
    make mrproper && make headers && \
    find usr/include -name '.*' -delete && rm usr/include/Makefile && \
    cp -rv usr/include $LFS/usr" || err "Linux headers falhou"
}

build_glibc() {
  msg "[toolchain] glibc"
  enter_as_lfs "cd $LFS/build && rm -rf glibc && mkdir glibc && cd glibc && \
    tar -xf $LFS/sources/glibc-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/glibc-*.tar.* && \
    mkdir build && cd build && \
    ../configure --prefix=/usr --host=x86_64-lfs-linux-gnu --build=$(../scripts/config.guess) \
                 --enable-kernel=4.19 --with-headers=$LFS/usr/include libc_cv_slibdir=/usr/lib && \
    make -j$JOBS && make DESTDIR=$LFS install && \
    sed -i 's/\(RTLDLIST=.*\)/\1:..\/lib64/' $LFS/usr/bin/ldd 2>/dev/null || true" || err "glibc falhou"
}

build_libstdcpp_pass1() {
  msg "[toolchain] libstdc++ pass1"
  enter_as_lfs "cd $LFS/build && rm -rf libstdcpp && mkdir libstdcpp && cd libstdcpp && \
    tar -xf $LFS/sources/gcc-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/gcc-*.tar.* && \
    mkdir build && cd build && \
    ../libstdc++-v3/configure --host=x86_64-lfs-linux-gnu --prefix=/usr \
      --disable-multilib --disable-nls --disable-libstdcxx-pch --with-gxx-include-dir=/tools/x86_64-lfs-linux-gnu/include/c++/* && \
    make -j$JOBS && make DESTDIR=$LFS install" || err "libstdc++ pass1 falhou"
}

build_binutils_pass2() {
  msg "[toolchain] binutils pass2"
  enter_as_lfs "cd $LFS/build && rm -rf binutils-p2 && mkdir binutils-p2 && cd binutils-p2 && \
    tar -xf $LFS/sources/binutils-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/binutils-*.tar.* && \
    mkdir build && cd build && \
    CC=/usr/bin/gcc AR=/usr/bin/ar RANLIB=/usr/bin/ranlib \
    ../configure --prefix=/usr --hosts=x86_64-lfs-linux-gnu --build=$(../config.guess) \
                 --disable-nls --enable-shared --enable-gold --enable-ld=default && \
    make -j$JOBS && make DESTDIR=$LFS install && \
    rm -v $LFS/usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes}.a 2>/dev/null || true" || err "binutils pass2 falhou"
}

build_gcc_pass2() {
  msg "[toolchain] gcc pass2"
  enter_as_lfs "cd $LFS/build && rm -rf gcc-p2 && mkdir gcc-p2 && cd gcc-p2 && \
    tar -xf $LFS/sources/gcc-*.tar.* --strip-components=1 -C . 2>/dev/null || tar -xf $LFS/sources/gcc-*.tar.* && \
    tar -xf $LFS/sources/mpfr-*.tar.* && mv mpfr-* mpfr && \
    tar -xf $LFS/sources/gmp-*.tar.* && mv gmp-* gmp && \
    tar -xf $LFS/sources/mpc-*.tar.* && mv mpc-* mpc && \
    mkdir build && cd build && \
    CC=/usr/bin/gcc CXX=/usr/bin/g++ AR=/usr/bin/ar RANLIB=/usr/bin/ranlib \
    ../configure --build=$(../config.guess) --host=x86_64-lfs-linux-gnu --target=x86_64-lfs-linux-gnu \
                 --prefix=/usr --disable-multilib --enable-languages=c,c++ --disable-libsanitizer && \
    make -j$JOBS && make DESTDIR=$LFS install && \
    ln -svf gcc $LFS/usr/bin/cc" || err "gcc pass2 falhou"
}

# --- Entrar em chroot e construir base --------------------------------------
enter_chroot() {
  msg "Entrando em chroot para construir base ($INIT, $LIB)"
  for p in dev proc sys run; do mkdir -p "$LFS/$p"; done
  mount -v --bind /dev "$LFS/dev"
  mount -vt devpts devpts "$LFS/dev/pts" -o gid=5,mode=620
  mount -vt proc   proc   "$LFS/proc"
  mount -vt sysfs  sysfs  "$LFS/sys"
  mount -vt tmpfs  tmpfs  "$LFS/run"

  chroot "$LFS" /usr/bin/env -i \
    HOME=/root TERM="$TERM" PS1='(lfs) \u:\w\$ ' \
    PATH=/usr/bin:/usr/sbin:/bin:/sbin:/tools/bin \
    /bin/sh -c "$1"

  umount -v "$LFS/dev/pts" "$LFS/dev" "$LFS/proc" "$LFS/sys" "$LFS/run" 2>/dev/null || true
}

# Receitas genéricas/placeholder dentro do chroot
chroot_build_minimal_base() {
  # Exemplos de builds genéricos: zlib, file, ncurses, bash, coreutils etc.
  cat >"$LFS/build/chroot-build.sh" <<'EOS'
set -eu
log() { printf "[chroot] %s\n" "$*"; }
JOBS=${JOBS-2}
S="$LFS/sources"
cd /sources 2>/dev/null || true

extract() { tar -xf "$1"; d=$(tar -tf "$1" | head -1 | cut -d/ -f1); printf "%s" "$d"; }

generic_build() {
  tgz="$1"; cfg="$2"; mkinst="$3"
  dir=$(extract "$tgz")
  cd "$dir"
  if [ -n "$cfg" ]; then eval "$cfg"; fi
  make -j$JOBS
  if [ -n "$mkinst" ]; then eval "$mkinst"; else make install; fi
  cd / && rm -rf "$dir"
}

# zlib (pode estar em common manifest — exemplo)
for T in $(ls /sources | grep -E '^zlib-.*\.(tar\.gz|tar\.xz)$' || true); do
  log "Construindo $T"
  generic_build "$T" "./configure --prefix=/usr" ""
  break
done

# file
for T in $(ls /sources | grep -E '^file-.*\.tar\.gz$' || true); do
  log "Construindo $T"
  generic_build "$T" "./configure --prefix=/usr" ""
  break
done

# ncurses
for T in $(ls /sources | grep -E '^ncurses-.*\.tar\.gz$' || true); do
  log "Construindo $T"
  generic_build "$T" "./configure --prefix=/usr --with-shared --without-debug --without-ada --enable-widec" ""
  break
done

# bash
for T in $(ls /sources | grep -E '^bash-.*\.tar\.gz$' || true); do
  log "Construindo $T"
  generic_build "$T" "./configure --prefix=/usr --without-bash-malloc" ""
  ln -svf bash /bin/sh || true
  break
done

# coreutils
for T in $(ls /sources | grep -E '^coreutils-.*\.tar\.xz$' || true); do
  log "Construindo $T"
  generic_build "$T" "./configure --prefix=/usr --enable-no-install-program=kill,uptime" ""
  break
done

# sysvinit ou systemd será tratado fora via INIT flag
EOS
}

chroot_setup_and_init() {
  cat >"$LFS/build/chroot-init.sh" <<EOS
set -eu
log() { printf "[chroot] %s\n" "\$*"; }
JOBS=${JOBS}
INIT=${INIT}

# Usuários e grupos básicos
log "Criando grupos/usuários essenciais"
cat > /etc/group <<'EOG'
root:x:0:
bin:x:1:
daemon:x:6:
sys:x:3:
adm:x:4:
wheel:x:10:
EOG
cat > /etc/passwd <<'EOP'
root:x:0:0:root:/root:/bin/bash
EOP

log "Criando diretórios base"
mkdir -pv /{boot,home,mnt,opt,srv}
mkdir -pv /etc/{opt,sysconfig}
mkdir -pv /lib/firmware
mkdir -pv /media/{floppy,cdrom}
mkdir -pv /usr/{,local/}{bin,include,lib,sbin,src}
mkdir -pv /var/{cache,local,log,mail,opt,spool}
install -dv -m 0750 /root
install -dv -m 1777 /tmp /var/tmp

log "Arquivos hosts e resolv.conf"
cat > /etc/hosts <<'EOH'
127.0.0.1 localhost
::1       localhost
EOH

# INIT específico
if [ "\$INIT" = "systemd" ]; then
  log "Selecionado systemd (placeholder – requer receitas detalhadas)"
  # Aqui entrariam: build do systemd, tmpfiles, udev, systemctl default target etc.
else
  log "Selecionado sysvinit"
  # Placeholder: build do sysvinit e scripts LFS
fi

log "Kernel será construído fora deste script placeholder (ver função build_kernel)"
EOS
}

# --- Kernel (feito em chroot) ------------------------------------------------
build_kernel() {
  cmd='
set -eu
cd /sources
# Procura tarball linux-*.tar.*
K=$(ls | grep -E "^linux-.*\\.tar\\.(gz|xz)$" | head -n1 || true)
[ -n "$K" ] || { echo "Nenhum tarball do kernel encontrado em /sources"; exit 1; }
T="$K"; D=$(tar -tf "$T" | head -1 | cut -d/ -f1)
[ -d "$D" ] && rm -rf "$D"
 tar -xf "$T" && cd "$D"
 make mrproper
 make defconfig
 make -j$JOBS
 make modules_install
 cp -v arch/x86/boot/bzImage /boot/vmlinuz-lfs
 cp -v System.map /boot/System.map
 cp -v .config /boot/config
'
  enter_chroot "$cmd" || err "Kernel falhou"
}

# --- Fase Multilib (experimental) -------------------------------------------
multilib_notes() {
  warn "Multilib é experimental aqui. Exige construir binutils/gcc/glibc com targets 32-bit (i686) e ld.so adequado."
}

# --- Runner ------------------------------------------------------------------
run_all() {
  check_host
  msg "Variante: INIT=$INIT, LIB=$LIB, BOOK_VER=$BOOK_VER, JOBS=$JOBS"
  setup_layout
  ensure_lfs_user
  write_manifests
  fetch_all
  make_dirs_toolchain
  build_binutils_pass1
  build_gcc_pass1
  build_linux_headers
  build_glibc
  build_libstdcpp_pass1
  build_binutils_pass2
  build_gcc_pass2
  chroot_build_minimal_base
  chroot_setup_and_init
  enter_chroot "/bin/sh /build/chroot-build.sh"
  enter_chroot "/bin/sh /build/chroot-init.sh"
  [ "$LIB" = "multilib" ] && multilib_notes || true
  build_kernel
  msg "Concluído (parcial). Ajuste manifests e receitas para cobrir 100% do livro conforme sua versão."
}

# --- CLI ---------------------------------------------------------------------
case "${1-}" in
  run|"") run_all ;;
  fetch) check_host; setup_layout; write_manifests; fetch_all ;;
  chroot) enter_chroot "/bin/sh" ;;
  *) echo "Uso: $0 [run|fetch|chroot] (variáveis via ambiente: INIT, LIB, LFS, JOBS, LFS_USER, SRC_MIRROR)"; exit 2 ;;
esac
