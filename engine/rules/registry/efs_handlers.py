from scanner.aws.collectors.efs import EFSDataCollector


def collect_efs_file_systems(
    collector: EFSDataCollector,
) -> list[dict]:
    return collector.collect_file_systems()


def collect_efs_access_points(
    collector: EFSDataCollector,
) -> list[dict]:
    return collector.collect_access_points()


EFS_DATA_SOURCE_HANDLERS = {
    "efs_file_systems": collect_efs_file_systems,
    "efs_access_points": collect_efs_access_points,
}
