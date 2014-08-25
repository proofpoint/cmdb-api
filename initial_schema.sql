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
  `fqdn` varchar(255) NOT NULL,
  `inventory_component_type` varchar(45) NOT NULL,
  `system_type` varchar(45) DEFAULT NULL,
  `status` varchar(20) DEFAULT 'idle',
  `ip_address` varchar(15) DEFAULT NULL,
  `mac_address` char(17) DEFAULT NULL,
  `data_center_code` varchar(6) DEFAULT NULL,
  `cage_code` varchar(45) DEFAULT NULL,
  `rack_code` varchar(45) DEFAULT NULL,
  `rack_position` int(2) DEFAULT NULL,
  `manufacturer` varchar(45) DEFAULT NULL,
  `product_name` varchar(45) DEFAULT NULL,
  `serial_number` varchar(255) DEFAULT NULL,
  `date_created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `date_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `agent_reported` timestamp NULL DEFAULT NULL,
  `hardware_class` varchar(45) DEFAULT NULL,
  `created_by` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`fqdn`),
  UNIQUE KEY `fqdn` (`fqdn`),
  UNIQUE KEY `mac_address` (`mac_address`),
  KEY `status` (`status`),
  KEY `cage_id` (`data_center_code`,`cage_code`),
  KEY `rack_id` (`data_center_code`,`rack_code`),
  KEY `inventory_component_type` (`inventory_component_type`),
  KEY `system_type` (`system_type`),
  KEY `fk_device_inv_comp_type_comp_type_type` (`inventory_component_type`),
  KEY `ip_address` (`ip_address`),
  CONSTRAINT `fk_device_data_center_code` FOREIGN KEY (`data_center_code`) REFERENCES `data_center` (`data_center_code`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `device_metadata`
--

DROP TABLE IF EXISTS `device_metadata`;
CREATE TABLE `device_metadata` (
  `metadata_id` int(11) NOT NULL AUTO_INCREMENT,
  `fqdn` varchar(255) NOT NULL,
  `metadata_name` varchar(45) NOT NULL,
  `metadata_value` text,
  `date_created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `date_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`metadata_id`),
  UNIQUE KEY `device_id` (`fqdn`,`metadata_name`),
  KEY `fk_device_metadata_device_fqdn` (`fqdn`),
  KEY `metadata_value` (`metadata_value`(100)),
  CONSTRAINT `fk_device_metadata_device_fqdn` FOREIGN KEY (`fqdn`) REFERENCES `device` (`fqdn`) ON DELETE CASCADE ON UPDATE CASCADE
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
-- Table structure for table `environments`
--

DROP TABLE IF EXISTS `environments`;
CREATE TABLE `environments` (
  `name` varchar(75) NOT NULL,
  `note` varchar(255) DEFAULT NULL,
  `environment_name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`name`)
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
