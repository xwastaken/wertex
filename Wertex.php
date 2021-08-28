<?php

use \parallel\Channel;
use \parallel\Runtime;

new Wertex(); //start server with class

final class Wertex {
	private const PORT = 19132;

	private $startTime;
	private $channels = [];

	public function __construct(){
		$logger = new Logger;
		$this->startTime = microtime(true);

		try {
			$logger->debug("Creating §achannels §fand §aruntimes§f..");

			$this->channels = [
				"runtimeReceive" => Channel::make("runtimeReceive", Channel::Infinite),
				"runtimeOutgoing" => Channel::make("runtimeOutgoing", Channel::Infinite),
				"pocketReceive" => Channel::make("pocketReceive", Channel::Infinite),
				"zlibReceive" => Channel::make("zlibReceive", Channel::Infinite)
			];
			$runtimes = [
				"raknetRuntime" => new Runtime(),
				"pocketRuntime" => new Runtime(),
				"zlibRuntime" => new Runtime()
			];

			$runtimes["raknetRuntime"]->run(function(Channel $receive, Channel $outgoing, Channel $zlibReceive, Channel $pocketReceive): void{
				$events = new \parallel\Events();
				$events->addChannel($receive);
				$events->setBlocking(false);

				$running = true;

				$serverId = mt_rand(-0xffffffff, 0xffffffff);
				$serverName = "MCPE;§a[1.1.x] §fsoftware §7[@xwastaken]§r;113;;". mt_rand(20, 50) .";200;". $serverId .";§econtact §7- §fvk.com/xwastaken§r;";

				$packed = [
					"server_guid" => pack("J", $serverId),
					"raknet_magic" => "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
				];

				$packed["unconnected_pong_buffer"] = "\x1c". pack("J", time()) . $packed["server_guid"] . $packed["raknet_magic"] . pack("n", strlen($serverName)) . $serverName;
				$packed["connection_internal_ids"] = "";

				$packddress = function(string $address): string{
					$buffer = "";
					foreach(explode(".", $address) as $addr){
						$buffer .= chr((~((int) $addr)) & 0xff);
					}
					return $buffer;
				};

				for($i = 0; $i < 10; ++$i){
					$packed["connection_internal_ids"] .= "\x04". $packddress("255.255.255.255") . pack("n", 19132);
				}

				$dataQueue = [];
				$ackQueue = [];
				$sessions = [];

				try {
					$pointTime = microtime(true);
					$secondTime = microtime(true);
					$loadAverage = [];

					while(true){
						$requests = 0;
						do {
							$startLoad = microtime(true);
							$event = $events->poll();
							if($event !== null && $event->type == \parallel\Events\Event\Type::Read){
								$events->addChannel($receive);
								$requests++;
								switch($event->value["identifier"]):
									case "stop":
										$running = false;
									break;
									case "name":
										$packed["unconnected_pong_buffer"] = "\x1c". pack("J", time()) . $packed["server_guid"] . $packed["raknet_magic"] . pack("n", strlen($event->value["server_name"])) . $event->value["server_name"];
									break;
									case "rcvpacket":
										//$outgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Received packet from §b". $event->value["address"][0] .":". $event->value["address"][1] ."§f: ". bin2hex($event->value["buffer"])]);
										switch($event->value["buffer"]{0}):
											case "\x01":
												$outgoing->send(["identifier" => "socket_send", "buffer" => $packed["unconnected_pong_buffer"], "length" => strlen($packed["unconnected_pong_buffer"]), "address" => $event->value["address"]]);
											break;
											case "\x05":
												if(!isset($sessions[$event->value["addressId"]])){
													$mtuSize = strlen(substr($event->value["buffer"], 18));
													$sessions[$event->value["addressId"]] = ["state" => 0, "mtuSize" => $mtuSize, "sequenceIndex" => 0, "reliableFrameIndex" => 0, "orderedFrameIndex" => 0, "compoundID" => 0, "fragments" => [], "timeout" => time() + 10];

													$buffer = "\x06". $packed["raknet_magic"] . $packed["server_guid"] ."\x00". pack("n", $mtuSize);
													$outgoing->send(["identifier" => "socket_send", "buffer" => $buffer, "length" => strlen($buffer), "address" => $event->value["address"]]);
												}
											break;
											case "\x07":
												if(isset($sessions[$event->value["addressId"]]) && $sessions[$event->value["addressId"]]["state"] == 0){
													$sessions[$event->value["addressId"]]["state"] = 1;
													
													$buffer = "\x08". $packed["raknet_magic"] . $packed["server_guid"] ."\x04". $packddress($event->value["address"][0]) . pack("n", $event->value["address"][1]) . pack("n", $event->value["parameters"][0]) ."\x00";
													$outgoing->send(["identifier" => "socket_send", "buffer" => $buffer, "length" => strlen($buffer), "address" => $event->value["address"]]);
												}
											break;
											case "\x84":
											case "\x8c":
												if(isset($sessions[$event->value["addressId"]]) && $sessions[$event->value["addressId"]]["state"] >= 1){
													$sequence = unpack("V", substr($event->value["buffer"], 1, 3) ."\x00")[1];
													$receive->send(["identifier" => "sndack", "immediately" => false, "sequence" => $sequence, "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
													$sessions[$event->value["addressId"]]["sequenceIndex"] = $sequence++;

													$offset = 4;
													for(; isset($event->value["buffer"][$offset]);){
														$flags = ord($event->value["buffer"]{$offset++});
														$reliability = ($flags & 0b11100000) >> 5;
														$length = (int) ceil(unpack("n", substr($event->value["buffer"], $offset, 2))[1] / 8);
														$offset += 2;

														if($reliability > 0){
															if($reliability >= 2 && $reliability != 5){
																$offset += 3;
															}

															if($reliability <= 4 && $reliability != 2){
																$offset += 4;
															}
														}

														if(($flags & 0b00010000) > 0){
															$compoundSize = unpack("N", substr($event->value["buffer"], $offset, 4))[1];
															$offset += 4;
															$compoundId = unpack("n", substr($event->value["buffer"], $offset, 2))[1];
															$offset += 2;
															$compoundIndex = unpack("N", substr($event->value["buffer"], $offset, 4))[1];
															$offset += 4;

															$receive->send(["identifier" => "fragment", "compoundSize" => $compoundSize, "compoundId" => $compoundId, "compoundIndex" => $compoundIndex, "buffer" => substr($event->value["buffer"], $offset, $length), "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
															$offset += $length;

															continue;
														}

														$packet = substr($event->value["buffer"], $offset, $length);
														$offset += $length;

														switch($packet{0}):
															case "\x00":
																$pingTime = substr($packet, 1, 8);
																$receive->send(["identifier" => "sndpacket", "immediately" => false, "sequence" => "need", "packets" => [0 => ["need", "\x03". $pingTime . $pingTime]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																$sessions[$event->value["addressId"]]["timeout"] = time() + 10;
															break;
															case "\x09":
																if($sessions[$event->value["addressId"]]["state"] == 1){
																	$sessions[$event->value["addressId"]]["state"] = 2;
																	$requestTime = substr($packet, 9, 8);
																	$receive->send(["identifier" => "sndpacket", "immediately" => true, "sequence" => 0, "packets" => [[0 => [false, "\x10\x04". $packddress($event->value["address"][0]) . pack("n", $event->value["address"][1]) ."\x00\x00". $packed["connection_internal_ids"] . $requestTime . $requestTime]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																}
															break;
															case "\x15":
																$pocketReceive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
															break;
															case "\xfe":
																if($sessions[$event->value["addressId"]]["state"] >= 2){
																	$zlibReceive->send(["identifier" => "decode", "buffer" => substr($packet, 1), "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																}
															break;
															default:
																$outgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Unhandled frame set packet from §b". $event->value["addressId"] ."§f: ". bin2hex($packet)]);
															break;
														endswitch;
													}
												}
											break;
											default:
												//$outgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Unhandled packet from §b". $event->value["address"][0] .":". $event->value["address"][1] ."§f: ". bin2hex($event->value["buffer"])]);
											break;
										endswitch;
									break;
									case "sndpacket":
										//var_dump($event->value);
										if($event->value["immediately"]){
											//var_dump($event->value);
											foreach($event->value["packets"] as $packets){
												foreach($packets as $reliability => $settings){
													if($settings[0] === "need"){
														$mtuSize = $sessions[$event->value["addressId"]]["mtuSize"] - 42;
														if($mtuSize > 0 && strlen($settings[1]) >= $mtuSize){
															$splitIndex = 0; $splitID = ($sessions[$event->value["addressId"]]["compoundID"]++ % 65535);
															$splitBuffers = str_split($settings[1], $mtuSize); $countBuffers = count($splitBuffers);
															//$orderedFrameIndex = $sessions[$event->value["addressId"]]["orderedFrameIndex"]++;

															foreach($splitBuffers as $splitBuffer){
																$buffer = "\x84". substr(pack("V", $event->value["sequence"]++), 0, -1) . chr(($reliability << 5) | 0b00010000) . pack("n", (strlen($splitBuffer) << 3));
																if($reliability > 0){
																	if($reliability >= 2 && $reliability != 5){
																		$buffer .= substr(pack("V", $sessions[$event->value["addressId"]]["reliableFrameIndex"]++), 0, -1);
																	}
																	if($reliability <= 4 && $reliability != 2){
																		$buffer .= substr(pack("V", $sessions[$event->value["addressId"]]["orderedFrameIndex"]++), 0, -1) ."\x00";
																	}
																}
																$buffer .= pack("N", $countBuffers) . pack("n", $splitID) . pack("N", $splitIndex++) . $splitBuffer;
																$outgoing->send(["identifier" => "socket_send", "buffer" => $buffer, "length" => strlen($buffer), "address" => $event->value["address"]]);
															}
															continue;
														}

														$buffer = "\x84". substr(pack("V", $event->value["sequence"]++), 0, -1) . chr($reliability << 5) . pack("n", (strlen($settings[1]) << 3));
														if($reliability > 0){
															if($reliability >= 2 && $reliability != 5){
																$buffer .= substr(pack("V", $sessions[$event->value["addressId"]]["reliableFrameIndex"]++), 0, -1);
															}
															if($reliability <= 4 && $reliability != 2){
																$buffer .= substr(pack("V", $sessions[$event->value["addressId"]]["orderedFrameIndex"]++), 0, -1) ."\x00";
															}
														}
														$buffer .= $settings[1];
														$outgoing->send(["identifier" => "socket_send", "buffer" => $buffer, "length" => strlen($buffer), "address" => $event->value["address"]]);
														continue;
													}

													$buffer = "\x84". substr(pack("V", $event->value["sequence"]++), 0, -1) .  chr(($reliability << 5) | ($settings[0] ? 0b00010000 : 0)) . pack("n", (strlen($settings[1]) << 3));
													if($reliability > 0){
														if($reliability >= 2 && $reliability != 5){
															$buffer .= substr(pack("V", $settings[2]), 0, -1);
														}
														if($reliability <= 4 && $reliability != 2){
															$buffer .= substr(pack("V", $settings[3]), 0, -1) ."\x00";
														}
													}
													if($settings[0]){
														$buffer .= pack("N", $settings[4]) . pack("n", $settings[5]) . pack("N", $settings[6]);
													}
													$buffer .= $settings[1];
													$outgoing->send(["identifier" => "socket_send", "buffer" => $buffer, "length" => strlen($buffer), "address" => $event->value["address"]]);
													continue;
												}
											}
											break;
										}

										if(isset($dataQueue[$event->value["addressId"]])){
											$dataQueue[$event->value["addressId"]]["sequence"] = ($event->value["sequence"] === "need" ? $sessions[$event->value["addressId"]]["sequenceIndex"]++ : $event->value["sequence"]);
											$dataQueue[$event->value["addressId"]]["packets"] = array_merge($dataQueue[$event->value["addressId"]]["packets"], [$event->value["packets"]]);
											//var_dump($dataQueue[$event->value["addressId"]]["packets"]);
											break;
										}

										$dataQueue[$event->value["addressId"]] = ["sequence" => ($event->value["sequence"] === "need" ? $sessions[$event->value["addressId"]]["sequenceIndex"]++ : $event->value["sequence"]), "packets" => [$event->value["packets"]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]];
									break;
									case "sndack":
										if($event->value["immediately"]){
											if($event->value["min"] == $event->value["max"]){
												$outgoing->send(["identifier" => "socket_send", "buffer" => "\xc0\x00\x01\x01". substr(pack("V", $event->value["min"]), 0, -1), "length" => 7, "address" => $event->value["address"]]);
												break;
											}

											$outgoing->send(["identifier" => "socket_send", "buffer" => "\xc0\x00\x01\x00". substr(pack("V", $event->value["min"]), 0, -1) . substr(pack("V", $event->value["max"]), 0, -1), "length" => 10, "address" => $event->value["address"]]);
											break;
										}

										if(isset($ackQueue[$event->value["addressId"]])){
											$ackQueue[$event->value["addressId"]]["max"] = $event->value["sequence"];
											break;
										}

										$ackQueue[$event->value["addressId"]] = ["min" => $event->value["sequence"], "max" => $event->value["sequence"], "address" => $event->value["address"]];
									break;
									case "fragment":
										if(!isset($sessions[$event->value["addressId"]]["fragments"][$event->value["compoundId"]][$event->value["compoundIndex"]])){
											$sessions[$event->value["addressId"]]["fragments"][$event->value["compoundId"]][$event->value["compoundIndex"]] = $event->value["buffer"];
										}

										if(count($sessions[$event->value["addressId"]]["fragments"][$event->value["compoundId"]]) >= $event->value["compoundSize"]){
											$buffer = "";
											for($i = 0; $i < $event->value["compoundSize"]; ++$i){
												$buffer .= $sessions[$event->value["addressId"]]["fragments"][$event->value["compoundId"]][$i];
											}
											$zlibReceive->send(["identifier" => "decode", "buffer" => substr($buffer, 1), "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
											unset($sessions[$event->value["addressId"]]["fragments"][$event->value["compoundId"]]);
										}
									break;
									case "disconnect": //from pocket thread
										if(isset($sessions[$event->value["address"]])){
											unset($sessions[$event->value["address"]]);
										}
									break;
								endswitch;

								$loadAverage[] = microtime(true) - $startLoad;
							}
						} while($running && $event !== null);
						if(!$running) break;

						if((microtime(true) - $pointTime) > 0.05){ //tick
							/*if(count($loadAverage) > 2){
								$outgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Handle §b". $requests ." §frequests (". round((array_sum($loadAverage) / count($loadAverage)) * 1000) ."ms)"]);
							}*/

							foreach($dataQueue as $identifier => $settings){
								$receive->send(["identifier" => "sndpacket", "immediately" => true, "sequence" => ($settings["sequence"] === "need" ? $sessions[$identifier]["sequenceIndex"]++ : $settings["sequence"]), "packets" => $settings["packets"], "address" => $settings["address"], "addressId" => $identifier]);
								unset($dataQueue[$identifier]);
							}

							foreach($ackQueue as $identifier => $settings){
								$receive->send(["identifier" => "sndack", "immediately" => true, "min" => $settings["min"], "max" => $settings["max"], "address" => $settings["address"], "addressId" => $identifier]);
								unset($ackQueue[$identifier]);
							}

							//var_dump($ackQueue);
							$pointTime = microtime(true);
						}

						if((microtime(true) - $secondTime) > 1){
							$currentTime = time();
							foreach($sessions as $identifier => $session){
								if($currentTime > $session["timeout"]){
									$pocketReceive->send(["identifier" => "disconnect", "address" => $identifier]);
								}
							}
							$secondTime = microtime(true);
						}
					}
				} catch(\ErrorException $exception){
					$outgoing->send(["identifier" => "logger", "level" => "error", "message" => $exception->getMessage() . PHP_EOL ."In the §c". $exception->getFile() ." §ffile on the §c". $exception->getLine() ." line§f! ". PHP_EOL . $exception->getTraceAsString()]);
				} finally {
					$outgoing->send(["identifier" => "logger", "level" => "debug", "message" => "RakNet thread stopped!"]);
				}
			}, [$this->channels["runtimeReceive"], $this->channels["runtimeOutgoing"], $this->channels["zlibReceive"], $this->channels["pocketReceive"]]);

			$runtimes["pocketRuntime"]->run(function(Channel $receive, Channel $zlibReceive, Channel $runtimeReceive, Channel $runtimeOutgoing): void{
				$events = new \parallel\Events();
				$events->addChannel($receive);
				$events->setBlocking(false);

				$running = true;
				$players = [];
				$entityId = 0;

				/** VARINT */
				$readUnsignedVarInt = function(string $buffer, int &$offset = 0): int{
					$value = 0;
					for($i = 0; $i < 35; $i += 7){
						if(!isset($buffer{$offset})){
							return -1; //not successfully
						}
						$b = ord($buffer{$offset++});
						$value |= (($b & 0x7f) << $i);
						if(($b & 0x80) === 0){
							return $value;
						}
					}
					return -1;
				};
				$readVarInt = function(string $buffer, int &$offset = 0) use($readUnsignedVarInt): int{
					$raw = $readUnsignedVarInt($buffer, $offset);
					$temp = (((($raw << 63) >> 63) ^ $raw) >> 1);
					return $temp ^ ($raw & (1 << 63));
				};
				$writeUnsignedVarInt = function(int $value): string{
					$buffer = "";
					$value &= 0xffffffff;
					for($i = 0; $i < 5; ++$i){
						if(($value >> 7) === 0){
							return $buffer . chr($value & 0x7f);
						}

						$buffer .= chr($value | 0x80);
						$value = (($value >> 7) & (PHP_INT_MAX >> 6));
					}
					return "null";
				};
				$writeVarInt = function(int $value) use($writeUnsignedVarInt): string{
					$v = ($value << 32 >> 32);
					return $writeUnsignedVarInt(($v << 1) ^ ($v >> 31));
				};

				/** VARLONG */
				$readUnsignedVarLong = function(string $buffer, int &$offset = 0): int{
					$value = 0;
					for($i = 0; $i < 63; $i += 7){
						if(!isset($buffer[$offset])){
							return -1; //not successfully
						}
						$b = ord($buffer[$offset++]);
						$value |= (($b & 0x7f) << $i);
						if(($b & 0x80) === 0){
							return $value;
						}
					}
					return -1;
				};
				$readVarInt = function(string $buffer, int &$offset = 0) use($readUnsignedVarLong): int{
					$raw = $readUnsignedVarLong($buffer, $offset);
					$temp = (((($raw << 63) >> 63) ^ $raw) >> 1);
					return $temp ^ ($raw & (1 << 63));
				};
				$writeUnsignedVarLong = function(int $value): string{
					$buffer = "";
					for($i = 0; $i < 10; ++$i){
						if(($value >> 7) === 0){
							return $buffer . chr($value & 0x7f);
						}

						$buffer .= chr($value | 0x80);
						$value = (($value >> 7) & (PHP_INT_MAX >> 6));
					}
					return "null";
				};
				$writeVarLong = function(int $value) use($writeUnsignedVarLong): string{
					return $writeUnsignedVarLong(($value << 1) ^ ($value >> 63));
				};

				$messages = [
					"unsupported_version" => "Your version is not supported by our server\n   Only version 1.1 is currently supported",
					"incorrect_skin" => "Incorrect skin", "incorrect_username" => "Incorrect name", "change_username" => "Change your name"
				];

				foreach($messages as $identifier => $message){
					$messages[$identifier] = chr(strlen($message)) . $message;
				}

				$spawnPosition = ["x" => 0, "y" => 2, "z" => 0]; //xyz
				$spawnRotation = ["yaw" => 0, "pitch" => 0]; //yaw & pitch

				$packed = [];
				$packed["startgame_subuffer"] = $writeVarInt(1) . //gamemode
					pack("g", $spawnPosition["x"]) . pack("g", $spawnPosition["y"]) . pack("g", $spawnPosition["z"]) . //position
					pack("g", $spawnRotation["yaw"]) . pack("g", $spawnRotation["pitch"]) . //rotation
					$writeVarInt(0) . //seed
					$writeVarInt(0) . //dimension
					$writeVarInt(0) . //generator
					$writeVarInt(2) . //world gamemode
					$writeVarInt(1) . //difficulty
					$writeVarInt($spawnPosition["x"]) . $writeUnsignedVarInt($spawnPosition["y"]) . $writeVarInt($spawnPosition["z"]) . //spawn position
					"\x01" . //has achievements disabled
					$writeVarInt(-1) . //day cycle stop time
					"\x00" . //edu mode
					pack("g", 0) . pack("g", 0) . //weather
					"\x01" . //commands enabled
					"\x01" . //is texture pack required
					$writeUnsignedVarInt(0) . //game rules
					$writeUnsignedVarInt(0) . //level id
					$writeUnsignedVarInt(4) . "test" . //world name
					$writeUnsignedVarInt(0) . //premium world template id
					"\x00" . //unknown bool
					strrev(pack("J", 0)); //current tick

				$packed["chunkradiusupdated_buffer"] = "\x46". $writeVarInt(8);
				$packed["fullchunksdatapacket"] = [];
				for($x = -2; $x < 2; ++$x){
					for($z = -2; $z < 2; ++$z){
						$packed["fullchunksdatapacket"][] = "\x3a". $writeVarInt($x) . $writeVarInt($z) ."\x00";
					}
				}
				$message = "Software author - @xwastaken". PHP_EOL ."You can contact me for cooperation :)";
				$packed["textpacket_author"] = "\x09\x00". chr(strlen($message)) . $message;
				unset($message);
				$packed["playstatus_buffers"] = [
					"login_success" => "\x02". pack("N", 0),
					"player_spawn" => "\x02". pack("N", 3)
				];
				$packed["resourcepack_buffers"] = [
					"packs_info" => "\x06\x00\x00\x00\x00\x00",
					"pack_stack" => "\x07\x00\x00\x00"
				];

				try {
					$pointTime = microtime(true);
					while(true){
						do {
							$event = $events->poll();
							if($event !== null && $event->type == \parallel\Events\Event\Type::Read){
								$events->addChannel($receive);
								switch($event->value["identifier"]):
									case "stop":
										$running = false;
									break;
									case "handle":
										$startTime = microtime(true);
										//var_dump("handle => ". bin2hex($event->value["buffer"]{0}));
										switch($event->value["buffer"]{0}):
											case "\x01": //login
												if(isset($players[$event->value["addressId"]])){
													break;
												}

												$protocol = unpack("N", substr($event->value["buffer"], 1, 4))[1];
												if($protocol >= 110 && $protocol <= 113){
													$offset = 6;
													$dataSize = $readUnsignedVarInt($event->value["buffer"], $offset);

													if($dataSize > 8192 && $dataSize < 65356){
														$data = substr($event->value["buffer"], $offset, $dataSize);
														$chainsSize = unpack("V", substr($data, 0, 4))[1] << 32 >> 32;

														if($chainsSize > 8 && $chainsSize < 2048){
															$players[$event->value["addressId"]] = ["state" => 0, "address" => $event->value["address"], "username" => [null, null], "clientUUID" => null, "entityId" => null, "clientId" => null, "skinId" => null, "skinData" => null, "langCode" => null, "world" => ["name" => "world", "chunksSpawned" => false, "firstChunksSpawned" => false], "position" => $spawnPosition, "rotation" => $spawnRotation, "spawned" => false];
															$chainData = json_decode(substr($data, 4, $chainsSize), true);

															foreach($chainData["chain"] as $chain){
																$tokens = explode(".", $chain);
																if(isset($tokens[1])){
																	$webtoken = json_decode(base64_decode($tokens[1]), true);
																	//var_dump($webtoken);
																	if(isset($webtoken["extraData"])){
																		$players[$event->value["addressId"]]["username"][0] = $webtoken["extraData"]["displayName"] ?? null;
																		$players[$event->value["addressId"]]["clientUUID"] = $webtoken["extraData"]["identity"] ?? null;
																	}
																	continue;
																}
																break;
															}

															$username = $players[$event->value["addressId"]]["username"][0];
															$userlen = strlen($username);
															//var_dump($userlen);

															if($userlen >= 1 && $userlen <= 16 && preg_match("/[^A-Za-z0-9_]/", $username) === 0){
																$lname = strtolower($username);
																if($lname !== "rcon" && $lname !== "console"){
																	$players[$event->value["addressId"]]["username"][1] = $lname;
																	$offset = 4 + $chainsSize;
																	$dataSize = unpack("V", substr($data, $offset, 4))[1] << 32 >> 32;

																	if($dataSize >= 8192 && $dataSize <= 65356){
																		$tokens = explode(".", substr($data, ($offset + 4), $dataSize));
																		if(isset($tokens[1])){
																			$clientData = json_decode(base64_decode($tokens[1]), true);

																			$players[$event->value["addressId"]]["clientId"] = $clientData["ClientRandomId"] ?? null;
																			$players[$event->value["addressId"]]["langCode"] = $clientData["LanguageData"] ?? null;
																			$players[$event->value["addressId"]]["skinId"] = $clientData["SkinId"] ?? null;

																			if(isset($clientData["SkinData"])){
																				$skinData = base64_decode($clientData["SkinData"]);
																				$skinlen = strlen($skinData);

																				if($skinlen == 8192 || $skinlen == 16384){
																					$players[$event->value["addressId"]]["skinData"] = $skinData;
																					if($players[$event->value["addressId"]]["clientUUID"] !== null && $players[$event->value["addressId"]]["skinId"] !== null){
																						$zlibReceive->send(["identifier" => "encode", "packets" => [0 => [$packed["playstatus_buffers"]["login_success"], $packed["resourcepack_buffers"]["packs_info"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																						break;
																					}
																				}

																				$zlibReceive->send(["identifier" => "encode", "packets" => [2 => ["\x05\x00". $messages["incorrect_skin"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																				$receive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
																				break;
																			}
																		}
																	}
																}

																$zlibReceive->send(["identifier" => "encode", "packets" => [2 => ["\x05\x00". $messages["change_username"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
																$receive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
																break;
															}

															$zlibReceive->send(["identifier" => "encode", "packets" => [2 => ["\x05\x00". $messages["incorrect_username"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
															$receive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
															break;
														}
													}

													$receive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
													break;
												}

												$zlibReceive->send(["identifier" => "encode", "packets" => [2 => ["isSplit" => false, "buffers" => ["\x05\x00". $messages["unsupported_version"]]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
												$receive->send(["identifier" => "disconnect", "address" => $event->value["addressId"]]);
											break;
											case "\x08": //resource pack response
												//var_dump(bin2hex($event->value["buffer"]));
												if(isset($players[$event->value["addressId"]])){
													if($players[$event->value["addressId"]]["state"] == 0 && $event->value["buffer"]{1} == "\x03"){
														$players[$event->value["addressId"]]["state"] = 1;
														$zlibReceive->send(["identifier" => "encode", "packets" => [2 => [$packed["resourcepack_buffers"]["pack_stack"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
														break;
													}

													if($players[$event->value["addressId"]]["state"] == 1 && $event->value["buffer"]{1} == "\x04"){
														$players[$event->value["addressId"]]["state"] = 2;
														$players[$event->value["addressId"]]["entityId"] = $entityId++;

														$zlibReceive->send(["identifier" => "encode", "packets" => [2 => ["\x0b". $writeVarLong($players[$event->value["addressId"]]["entityId"]) . $writeUnsignedVarLong($players[$event->value["addressId"]]["entityId"]) . $packed["startgame_subuffer"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
														break;
													}
												}
											break;
											case "\x45": //request chunk radius
												if(isset($players[$event->value["addressId"]]) && $players[$event->value["addressId"]]["state"] >= 2){
													$zlibReceive->send(["identifier" => "encode", "packets" => [2 => [$packed["chunkradiusupdated_buffer"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
													if(!$players[$event->value["addressId"]]["world"]["chunksSpawned"]){
														$players[$event->value["addressId"]]["world"]["chunksSpawned"] = true;
														$zlibReceive->send(["identifier" => "encode", "packets" => [2 => $packed["fullchunksdatapacket"]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
													}
													if(!$players[$event->value["addressId"]]["world"]["firstChunksSpawned"]){
														$players[$event->value["addressId"]]["world"]["firstChunksSpawned"] = true;
														$zlibReceive->send(["identifier" => "encode", "packets" => [2 => [$packed["playstatus_buffers"]["player_spawn"], $packed["textpacket_author"]]], "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
													}
													break;
												}
											break;
											default:
												//$runtimeOutgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Unhandled game packet from §b". $event->value["addressId"] ."§f: ". bin2hex($event->value["buffer"])]);
											break;
										endswitch;
										//var_dump(microtime(true) - $startTime);
									break;
									case "disconnect":
										$runtimeReceive->send(["identifier" => "disconnect", "address" => $event->value["address"]]);
										if(isset($players[$event->value["address"]])){
											unset($players[$event->value["address"]]);
										}
									break;
								endswitch;
							}
						} while($running && $event !== null);
						if(!$running) break;

						if((microtime(true) - $pointTime) > 0.05){ //tick
							$pointTime = microtime(true);
						}
					}
				} catch(\ErrorException $exception){
					$runtimeOutgoing->send(["identifier" => "logger", "level" => "error", "message" => $exception->getMessage() . PHP_EOL ."In the §c". $exception->getFile() ." §ffile on the §c". $exception->getLine() ." line§f! ". PHP_EOL . $exception->getTraceAsString()]);
				} finally {
					$runtimeOutgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Pocket thread stopped!"]);
				}
			}, [$this->channels["pocketReceive"], $this->channels["zlibReceive"], $this->channels["runtimeReceive"], $this->channels["runtimeOutgoing"]]);

			$runtimes["zlibRuntime"]->run(function(Channel $receive, Channel $pocketReceive, Channel $runtimeReceive, Channel $runtimeOutgoing): void{
				$events = new \parallel\Events();
				$events->addChannel($receive);
				$events->setBlocking(false);

				$running = true;

				$readUnsignedVarInt = function(string $buffer, int &$offset = 0): int{
					$value = 0;
					for($i = 0; $i < 28; $i += 7){
						if(!isset($buffer[$offset])){
							return -1; //not successfully
						}
						$b = ord($buffer[$offset++]);
						$value |= (($b & 0x7f) << $i);
						if(($b & 0x80) === 0){
							return $value;
						}
					}
					return -1;
				};
				$writeUnsignedVarInt = function(int $value): string{
					$buffer = "";
					$value &= 0xffffffff;
					for($i = 0; $i < 5; ++$i){
						if(($value >> 7) === 0){
							return $buffer . chr($value & 0x7f);
						}

						$buffer .= chr($value | 0x80);
						$value = (($value >> 7) & (PHP_INT_MAX >> 6));
					}
					return "null";
				};

				try {
					$pointTime = microtime(true);
					while(true){
						do {
							$event = $events->poll();
							if($event !== null && $event->type == \parallel\Events\Event\Type::Read){
								$events->addChannel($receive);
								switch($event->value["identifier"]):
									case "stop":
										$running = false;
									break;
									case "decode":
										try {
											$buffer = zlib_decode($event->value["buffer"], 1024 * 1024 * 4); //max 4MB
											//var_dump("decoded => ". bin2hex($buffer{0}));
											$offset = 0; $count = 0;
											while($offset < strlen($buffer) && $count < 500){
												if(($length = $readUnsignedVarInt($buffer, $offset)) >= 0){
													if(($packet = substr($buffer, $offset, $length)) != "\x21\x04\x00"){
														$pocketReceive->send(["identifier" => "handle", "buffer" => $packet, "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
														$offset += $length; $count++;
													}
													continue;
												}
												break;
											}
										} catch(\Throwable $throw){}
									break;
									case "encode":
										try {
											$frameSet = [];
											foreach($event->value["packets"] as $reliability => $buffers){
												$buffer = "";
												foreach($buffers as $packet){
													$packetLength = strlen($packet);
													if($packetLength > 127){
														if(($length = $writeUnsignedVarInt($packetLength)) === "null"){
															break;
														}
														$buffer .= $length . $packet;
														continue;
													}
													$buffer .= chr($packetLength) . $packet;
												}
												if(($encoded = zlib_encode($buffer, ZLIB_ENCODING_DEFLATE, 7)) !== false){
													$frameSet[$reliability] = ["need", "\xfe". $encoded];
												}
											}
											$runtimeReceive->send(["identifier" => "sndpacket", "immediately" => false, "sequence" => "need", "packets" => $frameSet, "address" => $event->value["address"], "addressId" => $event->value["addressId"]]);
										} catch(\Throwable $throw){}
									break;
								endswitch;
							}
						} while($running && $event !== null);
						if(!$running) break;

						if((microtime(true) - $pointTime) > 0.05){ //tick
							$pointTime = microtime(true);
						}
					}
				} catch(\ErrorException $exception){
					$runtimeOutgoing->send(["identifier" => "logger", "level" => "error", "message" => $exception->getMessage() . PHP_EOL ."In the §c". $exception->getFile() ." §ffile on the §c". $exception->getLine() ." line§f! ". PHP_EOL . $exception->getTraceAsString()]);
				} finally {
					$runtimeOutgoing->send(["identifier" => "logger", "level" => "debug", "message" => "Zlib thread stopped!"]);
				}
			}, [$this->channels["zlibReceive"], $this->channels["pocketReceive"], $this->channels["runtimeReceive"], $this->channels["runtimeOutgoing"]]);

			$logger->debug("Creating §asocket §fand bind to the §a". self::PORT ." §fport..");
			$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
			if(!(socket_bind($socket, "0.0.0.0", self::PORT))){
				throw new \ErrorException("Failed to bind to the ". self::PORT ." port!");
			}

			socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 1024 * 1024); //1MB
			//socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 0);
			socket_set_nonblock($socket);

			$logger->debug("Creating §ahandlers §ffor channels..");

			$events = new \parallel\Events();
			$events->addChannel($this->channels["runtimeOutgoing"]);
			$events->setBlocking(false); //setting up values for work

			if(function_exists("pcntl_signal")){
				$logger->debug("Setting up §apcntl §fhandler..");

				pcntl_signal(SIGHUP, [$this, "handlePcntl"]); //idk
				pcntl_signal(SIGINT, [$this, "handlePcntl"]); //ctrl+c
				pcntl_signal(SIGTERM, [$this, "handlePcntl"]); //kill

				pcntl_async_signals(true); //turn on async signals
			}

			$isRunning = true;
			$logger->info("Successfully started! (§a". round((microtime(true) - $this->startTime), 5) ."s.§f)");

			while(true){
				do {
					$event = $events->poll();
					if($event !== null){
						if($event->type == \parallel\Events\Event\Type::Read){
							$events->addChannel($this->channels["runtimeOutgoing"]);
							switch($event->value["identifier"]):
								case "stop":
									$isRunning = false;
								break;
								case "socket_send":
									socket_sendto($socket, $event->value["buffer"], $event->value["length"], 0, $event->value["address"][0], $event->value["address"][1]);
								break;
								case "logger":
									if($event->value["level"] == "error"){
										$this->handlePcntl(0); //server offline due error
									}

									$logger->log($event->value["level"], $event->value["message"]);
								break;
							endswitch;
						}
					}
				} while($isRunning && $event !== null);
				if(!$isRunning) break;

				for(; ($length = socket_recvfrom($socket, $buffer, 65535, 0, $source, $port)) > 0;){
					$this->channels["runtimeReceive"]->send(["identifier" => "rcvpacket", "buffer" => $buffer, "length" => $length, "address" => [$source, $port], "addressId" => $source .":". $port]);
				}
			}
		} catch(\Exception $exception){
			$logger->error($exception->getMessage() . PHP_EOL ."In the §c". $exception->getFile() ." §ffile on the §c". $exception->getLine() ." line§f! ". PHP_EOL . $exception->getTraceAsString());
		} finally {
			socket_close($socket); //closing socket for free port
			$logger->info("Successfully stopped!");
		}
	}

	public function handlePcntl(int $signo){
		$this->channels["pocketReceive"]->send(["identifier" => "stop"]); //other channels
		$this->channels["zlibReceive"]->send(["identifier" => "stop"]);
		$this->channels["runtimeReceive"]->send(["identifier" => "stop"]);

		time_sleep_until(microtime(true) + 0.25); //freeze for successfully stopping other channels
		$this->channels["runtimeOutgoing"]->send(["identifier" => "stop"]); 
	}
}

final class Logger {
	const ESCAPE = "\xc2\xa7"; //§
	private const DEBUG = true;

	private $prefixes = [
		"info" => "[INFO]",
		"notice" => "\x1b[38;5;87m[NOTICE]\x1b[m",
		"debug" => "\x1b[m\x1b[9m[DEBUG]\x1b[m",
		"error" => "\x1b[38;5;203m[ERROR]\x1b[m"
	];

	private $convertible = [
		self::ESCAPE ."0" => "\x1b[38;5;16m", //black
		self::ESCAPE ."1" => "\x1b[38;5;19m", //dark blue
		self::ESCAPE ."2" => "\x1b[38;5;34m", //dark green
		self::ESCAPE ."3" => "\x1b[38;5;37m", //dark aqua
		self::ESCAPE ."4" => "\x1b[38;5;124m", //dark red
		self::ESCAPE ."5" => "\x1b[38;5;127m", //purple
		self::ESCAPE ."6" => "\x1b[38;5;214m", //gold
		self::ESCAPE ."7" => "\x1b[38;5;145m", //gray
		self::ESCAPE ."8" => "\x1b[38;5;59m", //dark gray
		self::ESCAPE ."9" => "\x1b[38;5;63m", //blue
		self::ESCAPE ."a" => "\x1b[38;5;83m", //green
		self::ESCAPE ."b" => "\x1b[38;5;87m", //aqua
		self::ESCAPE ."c" => "\x1b[38;5;203m", //red
		self::ESCAPE ."d" => "\x1b[38;5;207m", //light purple
		self::ESCAPE ."e" => "\x1b[38;5;227m", //yellow
		self::ESCAPE ."f" => "\x1b[m", //reset because default color is white

		self::ESCAPE ."l" => "\x1b[1m", //bold
		self::ESCAPE ."o" => "\x1b[3m", //italic
		self::ESCAPE ."n" => "\x1b[4m", //underline
		self::ESCAPE ."m" => "\x1b[9m", //strikethrough
		self::ESCAPE ."r" => "\x1b[m" //reset
	];

	final public function info(string $message): void{
		$this->message($this->prefixes["info"], $message);
	}

	final public function notice(string $message): void{
		$this->message($this->prefixes["notice"], $message);
	}

	final public function debug(string $message): void{
		if(self::DEBUG){
			$this->message($this->prefixes["debug"], $message);
		}
	}

	final public function error(string $message): void{
		$this->message($this->prefixes["error"], "Handle exception: §c". $message);
	}

	final public function log(string $level, string $message): void{
		$this->message($this->prefixes[$level], $message);
	}

	final private function message(string $prefix, string $str): void{
		$newString = "";
		foreach(preg_split("/(". self::ESCAPE ."[0123456789abcdefklmnor])/", $str, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE) as $token){
			$newString .= isset($this->convertible[$token]) ? $this->convertible[$token] : $token;
		}

		foreach(explode(PHP_EOL, $newString) as $message){
			echo "\x1b[38;5;87m[". date("Y-m-d H:i:s") ."] \x1b[m". $prefix ." ". $message ."\x1b[m". PHP_EOL;
		}
	}
}