{
  description =
    "Vulnerablecode - A free and open vulnerabilities database and the packages they impact.";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs = {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
    ref = "20.09";
  };

  outputs = { self, nixpkgs }:
    let

      # Extract version from setup.py.
      version = builtins.head (builtins.match ''.*version=["']?([^"',]+).*''
        (builtins.readFile ./setup.py));

      vulnerablecode-src = ./.;
      poetryPatch = ./poetry-conversion.patch;
      # From commit cc7659f978b6ea17363511d25b7b30f52ccf45dd
      expectedRequirementstxtMd5sum = "b40c1c5c07315647fff28c220aafea10";

      # System types to support.
      supportedSystems = [ "x86_64-linux" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = f:
        nixpkgs.lib.genAttrs supportedSystems (system: f system);

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system:
        import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        });

    in {

      # A Nixpkgs overlay.
      overlay = final: prev:
        with final.pkgs; {

          # Create a patched version of Vulnerablecode.
          patched-vulnerablecode-src =
            runCommand "patched-vulnerablecode-src" { } ''
              cp -r ${vulnerablecode-src} $out
              chmod +w $out
              cd $out
              patch < ${poetryPatch}
            '';

          vulnerablecode = poetry2nix.mkPoetryApplication {
            projectDir =
              patched-vulnerablecode-src; # where to find {pyproject.toml,poetry.lock}
            src = ./.;
            python = python38;
            overrides = poetry2nix.overrides.withDefaults (self: super: {
              pygit2 = super.pygit2.overridePythonAttrs
                (old: { buildInputs = old.buildInputs ++ [ libgit2-glib ]; });
            });

            dontConfigure = true; # do not use ./configure
            dontBuild = true;

            installPhase = ''
              cp -r $src $out
            '';

            meta = {
              homepage = "https://github.com/nexB/vulnerablecode";
              license = lib.licenses.asl20;
            };
          };
        };

      # Provide a nix-shell env to work with vulnerablecode.
      devShell = forAllSystems (system:
        nixpkgsFor.${system}.mkShell {
          buildInputs = with nixpkgsFor.${system}; [
            postgresql
            vulnerablecode
          ];
          shellHook = ''
            export VULNERABLECODE_INSTALL_DIR=${
              self.packages.${system}.vulnerablecode
            }
            alias vulnerablecode-manage.py=$VULNERABLECODE_INSTALL_DIR/manage.py
          '';

        });

      # Provide some packages for selected system types.
      packages = forAllSystems
        (system: { inherit (nixpkgsFor.${system}) vulnerablecode; });

      # The default package for 'nix build'.
      defaultPackage =
        forAllSystems (system: self.packages.${system}.vulnerablecode);

      # Tests run by 'nix flake check' and by Hydra.
      checks = forAllSystems (system: {
        inherit (self.packages.${system}) vulnerablecode;

        # Additional tests, if applicable.
        vulnerablecode-pytest = with nixpkgsFor.${system};
          stdenv.mkDerivation {
            name = "vulnerablecode-test-${version}";

            buildInputs = [ wget ] ++ self.devShell.${system}.buildInputs;

            # Used by pygit2.
            # See https://github.com/NixOS/nixpkgs/pull/72544#issuecomment-582674047.
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            unpackPhase = "true";

            # Setup postgres, run migrations, run pytset and test-run the webserver.
            # See ${vulnerablecode}/README.md for the original instructions.
            # Notes:
            # - $RUNDIR is used to prevent postgres from accessings its default run dir at /run/postgresql.
            #   See also https://github.com/NixOS/nixpkgs/issues/83770#issuecomment-607992517.
            # - pytest can only be run with an running postgres database server.
            buildPhase = ''
              DATADIR=$(pwd)/pgdata
              RUNDIR=$(pwd)/run
              ENCODING="UTF-8"
              mkdir -p $RUNDIR
              initdb -D $DATADIR -E $ENCODING
              pg_ctl -D $DATADIR -o "-k $RUNDIR" -l $DATADIR/logfile start
              createuser --host $RUNDIR --no-createrole --no-superuser --login --inherit --createdb vulnerablecode
              createdb   --host $RUNDIR -E $ENCODING --owner=vulnerablecode --user=vulnerablecode --port=5432 vulnerablecode
              (
                export DJANGO_DEV=1
                ${vulnerablecode}/manage.py migrate
                (cd ${vulnerablecode} && pytest)
                ${vulnerablecode}/manage.py runserver &
                sleep 5
                ${wget}/bin/wget http://127.0.0.1:8000/api/
                kill %1 # kill webserver
              )
            '';

            installPhase = "mkdir -p $out";
          };
        vulnerablecode-requirements = with nixpkgsFor.${system};
          stdenv.mkDerivation {
            name = "vulnerablecode-requirements-${version}";

            unpackPhase = "true";

            buildPhase = ''
              EXPECTED=${expectedRequirementstxtMd5sum}
              ACTUAL=$(md5sum ${vulnerablecode}/requirements.txt | cut -d ' ' -f 1)
              if [[ $EXPECTED != $ACTUAL ]] ; then
                echo ""
                echo "The requirements.txt has changed!"
                echo "You should recreate ${baseNameOf poetryPatch}!"
                echo "1) Run make-poetry-conversion-patch.sh."
                echo "2) Update expectedRequirementstxtMd5sum in flake.nix."
                exit 1
              fi
            '';

            installPhase = "mkdir -p $out";
          };
      });
    };
}
