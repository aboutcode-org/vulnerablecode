{
  description =
    "Vulnerablecode - A free and open vulnerabilities database and the packages they impact.";

  inputs.nixpkgs = {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
    ref = "20.09";
  };

  inputs.machnix = {
    type = "github";
    owner = "DavHau";
    repo = "mach-nix";
    ref = "fe5255e6fd8df57e9507b7af82fc59dda9e9ff2b"; # 3.4.0
  };

  outputs = { self, nixpkgs, machnix }:
    let

      vulnerablecode-src = ./../..;
      requirements =
        builtins.readFile (vulnerablecode-src + "/requirements.txt");
      requirementsDev =
        builtins.readFile (vulnerablecode-src + "/requirements-dev.txt");

      # Extract version from setup.py.
      version = builtins.head (builtins.match ''.*version=["']?([^"',]+).*''
        (builtins.readFile (vulnerablecode-src + "/setup.py")));

      # Common shell code.
      libSh = ./lib.sh;

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

      # mach-nix instantiated for supported system types.
      machnixFor = forAllSystems (system:
        import machnix {
          pkgs = (nixpkgsFor.${system}).pkgs;
          python = "python38";

          # Pin pypi repo to a specific commit which includes all necessary
          # Python deps. The default version (which is updated with every
          # mach-nix release) is usually insufficient. Use
          # ./get-latest-pypi-deps-db.sh to obtain the data rev & hash.
          pypiDataRev =
            "897a7471aa4e83aab21d2c501e00fee3f440e0fe"; # 2022-02-21T08:57:22Z
          pypiDataSha256 =
            "03gnaq687gg9afb6i6czw4kzr1gbnzna15lfb26f9nszyfq3iyaj";

        });
      # This wrapper allows to setup both the production as well as the
      # development Python environments in the same way (albeit having
      # different requirements.txt).
      getPythonEnv = system: requirements:
        machnixFor.${system}.mkPython {
          requirements = ''
            ${requirements}
          '';
        };

    in {

      # A Nixpkgs overlay.
      overlay = final: prev:
        with final.pkgs; {

          pythonEnv = getPythonEnv system requirements;

          vulnerablecode = stdenv.mkDerivation {
            inherit version;
            name = "vulnerablecode-${version}";
            src = vulnerablecode-src;
            dontBuild = true; # do not use Makefile
            propagatedBuildInputs = [ pythonEnv postgresql gitMinimal ];

            postPatch = ''
              # Do not use absolute path.
              substituteInPlace vulnerablecode/settings.py \
                --replace 'STATIC_ROOT = "/var/vulnerablecode/static"' 'STATIC_ROOT = "./static"'
            '';

            installPhase = ''
              cp -r . $out
            '';
          };

        };

      # Provide a nix-shell env to work with vulnerablecode.
      devShell = forAllSystems (system:
        with nixpkgsFor.${system};
        mkShell {
          # will be available as env var in `nix develop` / `nix-shell`.
          VULNERABLECODE_INSTALL_DIR = vulnerablecode;
          buildInputs = [ vulnerablecode ];
          shellHook = ''
            alias vulnerablecode-manage.py=${vulnerablecode}/manage.py
          '';
        });

      # Provide some packages for selected system types.
      packages = forAllSystems
        (system: { inherit (nixpkgsFor.${system}) vulnerablecode; });

      # The default package for 'nix build'.
      defaultPackage =
        forAllSystems (system: self.packages.${system}.vulnerablecode);

      # Tests run by 'nix flake check' and by Hydra.
      checks = forAllSystems (system:
        let
          pythonEnvDev = getPythonEnv system ''
            ${requirements}
            ${requirementsDev}
          '';

        in {
          inherit (self.packages.${system}) vulnerablecode;

          vulnerablecode-test = with nixpkgsFor.${system};
            stdenv.mkDerivation {
              name = "${vulnerablecode.name}-test";

              buildInputs = [ wget vulnerablecode pythonEnvDev ];

              unpackPhase = "true";

              buildPhase = ''
                source ${libSh}
                initPostgres $(pwd)
                export SECRET_KEY=REALLY_SECRET
                ${vulnerablecode}/manage.py collectstatic --no-input
                ${vulnerablecode}/manage.py migrate
              '';

              doCheck = true;
              checkPhase = ''
                # Run pytest on the installed version. A running postgres
                # database server is needed.
                (
                  cd ${vulnerablecode}
                  black -l 100 --check .
                  pytest -m "not webtest"
                )

                # Launch the webserver and call the API.
                ${vulnerablecode}/manage.py runserver &
                sleep 2
                wget http://127.0.0.1:8000/api/
                kill %1 # kill background task (i.e. webserver)
              '';

              installPhase =
                "mkdir -p $out"; # make this derivation return success
            };
        });
    };
}
