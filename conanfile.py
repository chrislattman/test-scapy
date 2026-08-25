from conan import ConanFile


class PacketSniffer(ConanFile):
    settings = "os", "compiler", "build_type", "arch"

    generators = "CMakeToolchain", "CMakeDeps"

    def requirements(self):
        if self.settings.os == "Windows":
            self.requires("npcap/1.86")
        else:
            self.requires("libpcap/1.10.6")
