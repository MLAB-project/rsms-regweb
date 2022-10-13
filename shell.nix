with (import <nixpkgs> {});
stdenv.mkDerivation {
    name = "regweb";
    buildInputs = [ python3 python3Packages.cherrypy ];
}
