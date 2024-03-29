-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Gen 16, 2024 alle 17:10
-- Versione del server: 10.4.22-MariaDB
-- Versione PHP: 7.4.27

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dbds2`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `city`
--

CREATE TABLE `city` (
  `ID` int(11) NOT NULL,
  `name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dump dei dati per la tabella `city`
--

INSERT INTO `city` (`ID`, `name`) VALUES
(1, 'CATANIA'),
(2, 'SIRACUSA'),
(3, 'PALERMO'),
(4, 'TRAPANI'),
(5, 'ENNA'),
(6, 'RAGUSA'),
(7, 'CALTANISSETTA'),
(8, 'MESSINA'),
(9, 'AGRIGENTO'),
(10, 'ROMA'),
(11, 'VITERBO'),
(12, 'LATINA'),
(13, 'FROSINONE'),
(14, 'RIETI');

-- --------------------------------------------------------

--
-- Struttura della tabella `condition_notify`
--

CREATE TABLE `condition_notify` (
  `id` int(11) NOT NULL,
  `location` varchar(255) DEFAULT NULL,
  `t_min` int(11) DEFAULT NULL,
  `t_max` int(11) DEFAULT NULL,
  `precipitation` int(32) DEFAULT NULL,
  `humidity` int(32) DEFAULT NULL,
  `timestamp_temperature` timestamp NULL DEFAULT '2020-01-09 15:52:48',
  `timestamp_humidity` timestamp NULL DEFAULT '2020-01-09 15:52:48',
  `timestamp_precipitation` timestamp NULL DEFAULT '2020-01-09 15:52:48',
  `email` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


--
-- Indici per le tabelle `city`
--
ALTER TABLE `city`
  ADD PRIMARY KEY (`ID`);

--
-- Indici per le tabelle `condition_notify`
--
ALTER TABLE `condition_notify`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT per la tabella `city`
--
ALTER TABLE `city`
  MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT per la tabella `condition_notify`
--
ALTER TABLE `condition_notify`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=50;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
