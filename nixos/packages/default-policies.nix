{
  lib,
  stdenv,
  fetchFromGitHub,
}:

stdenv.mkDerivation rec {
  pname = "policy-store";
  version = "1.0.0";

  src = fetchFromGitHub {
    owner = "policy-store";
    repo = "gngram";
    rev = "deafult-policies";
    sha256 = "sha256-0000000000000000000000000000000000000000000=";
  };

  dontBuild = true;
  nativeBuildInputs = [ ];
  installPhase = ''
    mkdir -p $out/opa
    mkdir -p $out/vm-policies

    if [ -d "opa" ]; then
      cp -r opa/* $out/opa/
    fi

    if [ -d "vm-policies" ]; then
      for vm_path in vm-policies/*; do
        if [ -d "$vm_path" ]; then
          # Get the folder name (e.g., "vm-a")
          vm_name=$(basename "$vm_path")

          echo "Packaging $vm_name..."
          tar --sort=name \
              --mtime='@0' \
              --owner=0 --group=0 --numeric-owner \
              -czf "$out/vm-policies/$vm_name.tar.gz" \
              -C vm-policies "$vm_name"
        fi
      done
    fi
  '';

  meta = with lib; {
    description = "Default policy store";
    homepage = "https://github.com/tiiuae/ghaf-givc";
    license = licenses.asl20;
  };
}
