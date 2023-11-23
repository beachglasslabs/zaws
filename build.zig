const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zaws_mod = b.addModule("zaws", .{
        .source_file = Build.LazyPath.relative("src/zaws.zig"),
    });
    _ = zaws_mod;

    const unit_tests_step = b.step("unit-tests", "Run library tests");

    const unit_tests_exe = b.addTest(.{
        .root_source_file = .{ .path = "src/zaws.zig" },
        .target = target,
        .optimize = optimize,
    });
    const unit_tests_run = b.addRunArtifact(unit_tests_exe);
    unit_tests_step.dependOn(&unit_tests_run.step);
}
