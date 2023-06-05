const std = @import("std");

// This is not an imperative build script
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ltx",
        .link_libc = true,
        .target = target,
        .optimize = optimize,
    });

    exe.addIncludePath("msgpack");

    const std_cflags = [_][]const u8{
        "-std=gnu18",
        "-pedantic",
        "-Wall",
        "-W",
    };

    const dbg_cflags = [_][]const u8{
        "-D DEBUG",
        "-g",
    };

    const cflags = if (optimize == .Debug)
        &(std_cflags ++ dbg_cflags)
    else
        &std_cflags;

    exe.addCSourceFiles(&.{
        "ltx.c",
        "msgpack/message.c",
        "msgpack/unpack.c",
    }, cflags);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const sysinfo = b.addExecutable(.{
        .name = "sysinfo",
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .path = "cross/sysinfo.zig" },
    });

    b.installArtifact(sysinfo);
}
