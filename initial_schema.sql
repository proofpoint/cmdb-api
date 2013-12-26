--
-- Table structure for table `acl`
--

DROP TABLE IF EXISTS `acl`;
CREATE TABLE `acl` (
  `acl_id` int(11) NOT NULL AUTO_INCREMENT,
  `acl_group` varchar(75) DEFAULT NULL,
  `entity` varchar(75) DEFAULT NULL,
  `field` varchar(75) DEFAULT NULL,
  `logic` text,
  PRIMARY KEY (`acl_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `data_center`
--

DROP TABLE IF EXISTS `data_center`;
CREATE TABLE `data_center` (
  `data_center_code` varchar(6) NOT NULL,
  `data_center_vendor` varchar(255) DEFAULT NULL,
  `data_center_city` varchar(125) DEFAULT NULL,
  `data_center_country` varchar(45) DEFAULT NULL,
  `data_center_phone` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`data_center_code`),
  UNIQUE KEY `data_center_code` (`data_center_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `datacenter_subnet`
--

DROP TABLE IF EXISTS `datacenter_subnet`;
CREATE TABLE `datacenter_subnet` (
  `subnet` varchar(20) NOT NULL,
  `data_center_code` varchar(6) NOT NULL,
  `notes` varchar(256) DEFAULT NULL,
  UNIQUE KEY `subnet` (`subnet`),
  KEY `datacenter_code` (`data_center_code`),
  KEY `fk_dc_ip_range_datacenter_code` (`data_center_code`),
  CONSTRAINT `fk_dc_ip_range_datacenter_code` FOREIGN KEY (`data_center_code`) REFERENCES `data_center` (`data_center_code`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `device`
--

DROP TABLE IF EXISTS `device`;
CREATE TABLE `device` (
  `id` int(11) NOT NULL auto_increment,
  `fqdn` varchar(255) NOT NULL default '',
  `inventory_component_type` varchar(45) default NULL,
  `system_type` varchar(45) default NULL,
  `status` varchar(20) default NULL,
  `ip_address` varchar(15) default NULL,
  `mac_address` char(17) default NULL,
  `data_center_code` varchar(6) default NULL,
  `cage_code` varchar(45) default NULL,
  `rack_code` varchar(45) default NULL,
  `rack_position` int(2) default NULL,
  `manufacturer` varchar(45) default NULL,
  `product_name` varchar(45) default NULL,
  `serial_number` varchar(255) default NULL,
  `date_created` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  `date_modified` timestamp NOT NULL default '0000-00-00 00:00:00',
  `agent_reported` timestamp NOT NULL default '0000-00-00 00:00:00',
  `hardware_class` varchar(45) default NULL,
  `created_by` varchar(100) default NULL,
  `operating_system` varchar(20) default NULL,
  `bios_version` varchar(20) default NULL,
  `audit_info` varchar(45) default NULL,
  `bios_vendor` varchar(20) default NULL,
  `cloud` varchar(20) default NULL,
  `operating_system_release` varchar(45) default NULL,
  `asset_tag_number` varchar(45) default NULL,
  `blade_chassis_serial` varchar(45) default NULL,
  `config_agent_summary` varchar(255) default NULL,
  `pps_clusterid` varchar(45) default NULL,
  `ipv6_address` varchar(45) default NULL,
  `roles` varchar(255) default NULL,
  `disk_drive_count` int(11) default NULL,
  `environment_name` varchar(100) default NULL,
  `pps_agents` text,
  `warranty_info` varchar(255) default NULL,
  `pps_customerid` varchar(75) default NULL,
  `kernel_release` varchar(45) default NULL,
  `raidvolumes` varchar(255) default NULL,
  `raiddrivestatus` varchar(30) default NULL,
  `power_consumption_avg` int(11) default NULL,
  `drac_macaddress` char(17) default NULL,
  `pic_instance` varchar(40) default NULL,
  `file_systems` varchar(255) default NULL,
  `config_agent_timestamp` timestamp NOT NULL default '0000-00-00 00:00:00',
  `netdriver_firmware` varchar(45) default NULL,
  `netdriver_version` varchar(20) default NULL,
  `customers` varchar(255) default NULL,
  `agent_type` varchar(45) default NULL,
  `svc_id` int(11) default NULL,
  `pps_config_role` varchar(255) default NULL,
  `host_fqdn` varchar(255) default NULL,
  `power_supply_watts` double default NULL,
  `drac` varchar(15) default NULL,
  `power_consumption_peak` int(11) default NULL,
  `power_consumption_peaktime` timestamp NOT NULL default '0000-00-00 00:00:00',
  `physical_processor_count` int(11) default NULL,
  `memory_size` varchar(15) default NULL,
  `raidbaddrives` varchar(15) default NULL,
  `size` varchar(20) default NULL,
  `netdriver_duplex` varchar(10) default NULL,
  `primary_interface` varchar(10) default NULL,
  `interfaces` varchar(255) default NULL,
  `raidcontroller` varchar(255) default NULL,
  `processors` varchar(45) default NULL,
  `is_virtual` tinyint(1) default NULL,
  `raiddrives` varchar(45) default NULL,
  `raidtype` varchar(45) default NULL,
  `image` varchar(45) default NULL,
  `tags` varchar(100) default NULL,
  `virtual` varchar(15) default NULL,
  `netdriver` varchar(20) default NULL,
  `power_supply_count` int(11) default NULL,
  `notes` text,
  `drac_version` varchar(45) default NULL,
  `netdriver_speed` varchar(15) default NULL,
  `config_agent_output` text,
  `pps_version` varchar(15) default NULL,
  `config_agent_status` varchar(20) default NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `fqdn` (`fqdn`),
  UNIQUE KEY `mac_address` (`mac_address`),
  KEY `host_fqdn` (`host_fqdn`),
  KEY `status` (`status`),
  KEY `cage_id` (`data_center_code`,`cage_code`),
  KEY `rack_id` (`data_center_code`,`rack_code`),
  KEY `inventory_component_type` (`inventory_component_type`),
  KEY `system_type` (`system_type`),
  KEY `fk_device_inv_comp_type_comp_type_type` (`inventory_component_type`),
  KEY `ip_address` (`ip_address`),
  CONSTRAINT `fk_device_data_center_code` FOREIGN KEY (`data_center_code`) REFERENCES `data_center` (`data_center_code`) ON UPDATE CASCADE,
  CONSTRAINT `fk_device_inv_comp_type_comp_type_type` FOREIGN KEY (`inventory_component_type`) REFERENCES `component_type` (`type`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `hardware_model`
--

DROP TABLE IF EXISTS `hardware_model`;
CREATE TABLE `hardware_model` (
  `manufacturer` varchar(150) NOT NULL,
  `product_name` varchar(45) NOT NULL,
  `hardware_class` varchar(45) NOT NULL,
  `power_supply_count` int(10) DEFAULT NULL,
  `power_supply_watts` int(10) DEFAULT NULL,
  `size` int(2) DEFAULT NULL,
  `url` varchar(4000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `change_queue`
--

DROP TABLE IF EXISTS `change_queue`;
CREATE TABLE `change_queue` (
  `id` int(9) unsigned NOT NULL AUTO_INCREMENT,
  `change_ip` varchar(20) NOT NULL,
  `change_user` varchar(50) NOT NULL,
  `change_time` datetime NOT NULL,
  `change_content` text NOT NULL,
  `entity` varchar(75) NOT NULL,
  `entity_key` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `entity_key_change_content` (`entity_key`,`change_content`(250)),
  KEY `entity_key` (`entity_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `inv_audit`
--

DROP TABLE IF EXISTS `inv_audit`;
CREATE TABLE `inv_audit` (
  `entity_name` varchar(100) NOT NULL,
  `field_name` varchar(100) NOT NULL,
  `entity_key` varchar(250) NOT NULL,
  `old_value` text,
  `new_value` text,
  `change_time` datetime NOT NULL,
  `change_user` varchar(100) DEFAULT NULL,
  `change_ip` varchar(35) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `inv_normalizer`
--

DROP TABLE IF EXISTS `inv_normalizer`;
CREATE TABLE `inv_normalizer` (
  `id` int(9) unsigned NOT NULL AUTO_INCREMENT,
  `entity_name` varchar(50) DEFAULT NULL,
  `field_name` varchar(50) DEFAULT NULL,
  `matcher` varchar(120) DEFAULT NULL,
  `sub_value` varchar(120) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `pool`
--

DROP TABLE IF EXISTS `pool`;
CREATE TABLE `pool` (
  `name` varchar(75) DEFAULT NULL,
  `monitor` varchar(75) DEFAULT NULL,
  `members` varchar(255) DEFAULT NULL,
  `config` text,
  `lb_fqdn` varchar(75) DEFAULT NULL,
  `status` varchar(25) DEFAULT NULL,
  `comkey` varchar(125) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `rack`
--

DROP TABLE IF EXISTS `rack`;
CREATE TABLE `rack` (
  `rack_code` varchar(45) NOT NULL,
  `data_center_code` varchar(6) NOT NULL,
  `cage_code` varchar(45) NOT NULL,
  `power_watts` int(11) DEFAULT NULL,
  PRIMARY KEY (`rack_code`,`data_center_code`,`cage_code`),
  KEY `datacenter_code` (`data_center_code`),
  KEY `cage` (`cage_code`),
  KEY `fk_rack_datacenter_code` (`data_center_code`),
  CONSTRAINT `fk_rack_datacenter_code` FOREIGN KEY (`data_center_code`) REFERENCES `data_center` (`data_center_code`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `role_id` varchar(100) NOT NULL,
  `role_name` varchar(200) NOT NULL,
  `blessed` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `service_instance`
--

DROP TABLE IF EXISTS `service_instance`;
CREATE TABLE `service_instance` (
  `svc_id` mediumint(9) NOT NULL AUTO_INCREMENT,
  `name` varchar(75) NOT NULL,
  `type` varchar(25) DEFAULT NULL,
  `note` varchar(255) DEFAULT NULL,
  `environment_name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`svc_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `service_instance_data`
--

DROP TABLE IF EXISTS `service_instance_data`;
CREATE TABLE `service_instance_data` (
  `data_id` mediumint(9) NOT NULL AUTO_INCREMENT,
  `svc_id` mediumint(9) NOT NULL,
  `data_key` varchar(45) NOT NULL,
  `data_value` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`data_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `snat`
--

DROP TABLE IF EXISTS `snat`;
CREATE TABLE `snat` (
  `name` varchar(55) DEFAULT NULL,
  `vlans` varchar(55) DEFAULT NULL,
  `origins` varchar(255) DEFAULT NULL,
  `config` text,
  `lb_fqdn` varchar(155) DEFAULT NULL,
  `status` varchar(25) DEFAULT NULL,
  `comkey` varchar(125) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `groups` varchar(255) DEFAULT NULL,
  `systemuser` varchar(25) DEFAULT NULL,
  `username` varchar(66) DEFAULT NULL,
  `writeaccess` varchar(25) DEFAULT NULL,
  `sshkey` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT into `user` set groups="Admin", systemuser="0",username="admin",writeaccess="1";

--
-- Table structure for table `vip`
--

DROP TABLE IF EXISTS `vip`;
CREATE TABLE `vip` (
  `ip_address` varchar(45) NOT NULL,
  `pool` varchar(255) DEFAULT NULL,
  `name` varchar(160) NOT NULL,
  `vlans` varchar(160) DEFAULT NULL,
  `lb_fqdn` varchar(75) DEFAULT NULL,
  `status` varchar(25) DEFAULT NULL,
  `config` text,
  `comkey` varchar(125) NOT NULL,
  PRIMARY KEY (`comkey`),
  KEY `domain_name` (`pool`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
