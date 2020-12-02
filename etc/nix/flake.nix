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

      vulnerablecode-src = ./../..;

      # Extract version from setup.py.
      version = builtins.head (builtins.match ''.*version=["']?([^"',]+).*''
        (builtins.readFile (vulnerablecode-src + "/setup.py")));

      # From commit 7f8ae6399b02b1d508689b303f117e2f03f7854a
      expectedRequirementstxtMd5sum = "7ea5fec4096b9c532450d68fad721017";

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

          # Create a mock project.
          mockPoetryProject =
            runCommand "mockPoetryProject" { buildInputs = [ rename ]; } ''
              EXPECTED=${expectedRequirementstxtMd5sum}
              ACTUAL=$(md5sum ${vulnerablecode-src}/requirements.txt | cut -d ' ' -f 1)
              if [[ $EXPECTED != $ACTUAL ]] ; then
                echo ""
                echo "The requirements.txt has changed!"
                echo "1) Run make-poetry-conversion-patch.sh."
                echo "2) Update expectedRequirementstxtMd5sum in flake.nix."
                exit 1
              fi

              mkdir $out
              cd $out
              cp ${vulnerablecode-src}/etc/nix/{pyproject.toml,poetry.lock}.generated .
              rename 's/.generated$//' *.generated
            '';

          vulnerablecode = poetry2nix.mkPoetryApplication rec {
            projectDir = mockPoetryProject; # where to find {pyproject.toml,poetry.lock}
            src = vulnerablecode-src;
            python = python38;
            overrides = poetry2nix.overrides.withDefaults (self: super: {
              pygit2 = super.pygit2.overridePythonAttrs
                (old: { buildInputs = old.buildInputs ++ [ libgit2-glib ]; });
            });

            patchPhase = ''
              # Make sure "our" pycodestyle binary is used.
              sed -i 's/join(bin_dir, "pycodestyle")/"pycodestyle"/' vulnerabilities/tests/test_basics.py
              '';

            propagatedBuildInputs = [ postgresql ];

            dontConfigure = true; # do not use ./configure
            dontBuild = true;

            installPhase = ''
              cp -r . $out
            '';

            meta = {
              homepage = "https://github.com/nexB/vulnerablecode";
              license = lib.licenses.asl20;
            };
          };
        };

      # Provide a nix-shell env to work with vulnerablecode.
      devShell = forAllSystems (system:
        with nixpkgsFor.${system};
        mkShell rec {
          # will be available as env var in `nix develop`
          VULNERABLECODE_INSTALL_DIR = vulnerablecode;
          buildInputs = [ vulnerablecode ];
          shellHook = ''
            alias vulnerablecode-manage.py=${VULNERABLECODE_INSTALL_DIR}/manage.py
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

            buildInputs = [ wget vulnerablecode ];

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
      });
    };
}
