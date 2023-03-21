{
  description =
    "Vulnerablecode - A free and open vulnerabilities database and the packages they impact.";

  inputs.nixpkgs = {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
    ref = "20.09";
  };

  inputs.machnix.url = "mach-nix/3.5.0";

  outputs = { self, nixpkgs, machnix }:
    let

      vulnerablecode-src = ./../..;
      requirements =
        builtins.readFile (vulnerablecode-src + "/requirements.txt");
      requirementsDev =
        builtins.readFile (vulnerablecode-src + "/requirements-dev.txt");

      # Extract version from setup.cfg.
      version = builtins.head (builtins.match ''.*version = ([^\\s]+).*''
        (builtins.readFile (vulnerablecode-src + "/setup.cfg")));

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
          pypiDataRev = "df9e0d20f5510282c5c2b51ab019a7451fd650e2"; # 2023-03-21T09:43:14Z
          pypiDataSha256 = "151qbskwi1jgkxzdr8kf06n44hc61f2806hif61bf0cr6xhk00yn";
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
                # Work on a local copy.
                cp -r ${vulnerablecode} ./vulnerablecode
                cd ./vulnerablecode
                chmod -R +w .

                source ./etc/nix/lib.sh

                setupDevEnv
              '';

              doCheck = true;
              checkPhase = ''
                export PYTHON_EXE=${pythonEnvDev}/bin/python3 # use correct python
                make check
                make test

                # Launch the webserver and call the API.
                make run &
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
