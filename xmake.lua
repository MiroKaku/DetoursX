-- xmake
set_xmakever("2.5.5")
add_rules("plugin.vsxmake.autoupdate")

-- global
add_rules("mode.debug", "mode.release")
set_warnings("allextra", "error")
set_languages("c11", "cxx17")

if is_mode("debug") then
    add_defines("DEBUG")
end

-- target
target("Detours")
    set_kind("static")
    add_files("Detours/src/*.cpp|uimports.cpp")

target("Unittest")
    set_kind("shared")
    add_deps("Detours")
    add_files("test/unittest.cpp", "test/module.def")
    if is_arch("x64") then
        set_basename("Unittest64")
    else
        set_basename("Unittest32")
    end

target("DetoursX")
    add_rules("wdk.static", "wdk.env.wdm")
    add_files("src/*.cpp|uimports.cpp")

target("UnittestX")
    add_rules("wdk.driver", "wdk.env.wdm")
    set_values("wdk.sign.mode", "test")
    add_deps("DetoursX")
    add_ldflags("/INTEGRITYCHECK")
    add_files("test/unittest.cpp", "test/unittest.inf")

--
-- If you want to known more usage about xmake, please see https://xmake.io
--
-- ## FAQ
--
-- You can enter the project directory firstly before building project.
--
--   $ cd projectdir
--
-- 1. How to build project?
--
--   $ xmake
--
-- 2. How to configure project?
--
--   $ xmake f -p [macosx|linux|iphoneos ..] -a [x86_64|i386|arm64 ..] -m [debug|release]
--
-- 3. Where is the build output directory?
--
--   The default output directory is `./build` and you can configure the output directory.
--
--   $ xmake f -o outputdir
--   $ xmake
--
-- 4. How to run and debug target after building project?
--
--   $ xmake run [targetname]
--   $ xmake run -d [targetname]
--
-- 5. How to install target to the system directory or other output directory?
--
--   $ xmake install
--   $ xmake install -o installdir
--
-- 6. Add some frequently-used compilation flags in xmake.lua
--
-- @code
--    -- add debug and release modes
--    add_rules("mode.debug", "mode.release")
--
--    -- add macro defination
--    add_defines("NDEBUG", "_GNU_SOURCE=1")
--
--    -- set warning all as error
--    set_warnings("all", "error")
--
--    -- set language: c99, c++11
--    set_languages("c99", "c++11")
--
--    -- set optimization: none, faster, fastest, smallest
--    set_optimize("fastest")
--
--    -- add include search directories
--    add_includedirs("/usr/include", "/usr/local/include")
--
--    -- add link libraries and search directories
--    add_links("tbox")
--    add_linkdirs("/usr/local/lib", "/usr/lib")
--
--    -- add system link libraries
--    add_syslinks("z", "pthread")
--
--    -- add compilation and link flags
--    add_cxflags("-stdnolib", "-fno-strict-aliasing")
--    add_ldflags("-L/usr/local/lib", "-lpthread", {force = true})
--
-- @endcode
--
