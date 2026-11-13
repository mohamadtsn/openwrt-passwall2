"use strict";

import { readfile } from "fs";
import { uname } from "luci.core";

function readUptime() {
	let raw = readfile("/proc/uptime");
	let m = raw ? match(raw, /^(\d+)/) : null;
	return m ? +m[1] : 0;
}

let u = uname();

return {
	system: {
		board: {
			call: function() {
				return {
					kernel: u.release ?? "6.6.0",
					hostname: u.nodename ?? "passwall2-dev",
					system: u.machine ?? "x86_64",
					model: "OpenWrt Docker Sandbox",
					board_name: "docker,x86-64",
					rootfs_type: "overlay",
					release: {
						distribution: "OpenWrt",
						version: "24.10.1",
						revision: "r28597-0425664679",
						target: "x86/64",
						description: "OpenWrt 24.10.1 r28597-0425664679"
					}
				};
			}
		},
		info: {
			call: function() {
				return {
					uptime: readUptime(),
					localtime: time(),
					load: [0, 0, 0],
					memory: {
						total: 1073741824,
						free: 536870912,
						shared: 0,
						buffered: 0,
						available: 536870912
					}
				};
			}
		}
	}
};
