from unittest.mock import Mock

from scanner.aws.collectors.fsx import FSxDataCollector


def test_collect_file_systems_normalizes_fsx_types():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-openzfs",
            "ResourceARN": "arn:aws:fsx:example:openzfs",
            "FileSystemType": "OPENZFS",
            "OpenZFSConfiguration": {
                "CopyTagsToBackups": True,
                "CopyTagsToVolumes": False,
                "DeploymentType": "SINGLE_AZ_1",
            },
        },
        {
            "FileSystemId": "fs-lustre",
            "FileSystemType": "LUSTRE",
            "LustreConfiguration": {
                "CopyTagsToBackups": True,
            },
        },
        {
            "FileSystemId": "fs-ontap",
            "FileSystemType": "ONTAP",
            "OntapConfiguration": {
                "DeploymentType": "MULTI_AZ_2",
            },
        },
        {
            "FileSystemId": "fs-windows",
            "FileSystemType": "WINDOWS",
            "WindowsConfiguration": {
                "DeploymentType": "MULTI_AZ_1",
            },
        },
    ]

    collector = FSxDataCollector(service)

    assert collector.collect_file_systems() == [
        {
            "resource_id": "fs-openzfs",
            "resource_type": "fsx_file_system",
            "resource_arn": "arn:aws:fsx:example:openzfs",
            "file_system_type": "OPENZFS",
            "openzfs_copy_tags_to_backups": True,
            "openzfs_copy_tags_to_volumes": False,
            "openzfs_deployment_type": "SINGLE_AZ_1",
            "lustre_copy_tags_to_backups": False,
            "ontap_deployment_type": None,
            "windows_deployment_type": None,
        },
        {
            "resource_id": "fs-lustre",
            "resource_type": "fsx_file_system",
            "resource_arn": None,
            "file_system_type": "LUSTRE",
            "openzfs_copy_tags_to_backups": False,
            "openzfs_copy_tags_to_volumes": False,
            "openzfs_deployment_type": None,
            "lustre_copy_tags_to_backups": True,
            "ontap_deployment_type": None,
            "windows_deployment_type": None,
        },
        {
            "resource_id": "fs-ontap",
            "resource_type": "fsx_file_system",
            "resource_arn": None,
            "file_system_type": "ONTAP",
            "openzfs_copy_tags_to_backups": False,
            "openzfs_copy_tags_to_volumes": False,
            "openzfs_deployment_type": None,
            "lustre_copy_tags_to_backups": False,
            "ontap_deployment_type": "MULTI_AZ_2",
            "windows_deployment_type": None,
        },
        {
            "resource_id": "fs-windows",
            "resource_type": "fsx_file_system",
            "resource_arn": None,
            "file_system_type": "WINDOWS",
            "openzfs_copy_tags_to_backups": False,
            "openzfs_copy_tags_to_volumes": False,
            "openzfs_deployment_type": None,
            "lustre_copy_tags_to_backups": False,
            "ontap_deployment_type": None,
            "windows_deployment_type": "MULTI_AZ_1",
        },
    ]


def test_collect_file_systems_skips_missing_ids():
    service = Mock()

    service.list_file_systems.return_value = [
        {"FileSystemType": "OPENZFS"},
        {"FileSystemId": ""},
        {"FileSystemId": "fs-valid"},
    ]

    collector = FSxDataCollector(service)

    result = collector.collect_file_systems()

    assert len(result) == 1
    assert result[0]["resource_id"] == "fs-valid"


def test_collect_file_systems_caches_service_response():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-1",
            "FileSystemType": "LUSTRE",
        },
    ]

    collector = FSxDataCollector(service)

    collector.collect_file_systems()
    collector.collect_file_systems()

    service.list_file_systems.assert_called_once()
