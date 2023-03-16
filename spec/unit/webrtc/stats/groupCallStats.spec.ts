/*
Copyright 2020 - 2023 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { GroupCallStats } from "../../../../src/webrtc/stats/groupCallStats";

const GROUP_CALL_ID = "GROUP_ID";
const LOCAL_USER_ID = "LOCAL_USER_ID";
const TIME_INTERVAL = 10000;

describe("GroupCallStats", () => {
    let stats: GroupCallStats;
    beforeEach(() => {
        stats = new GroupCallStats(GROUP_CALL_ID, LOCAL_USER_ID, TIME_INTERVAL);
        // @ts-ignore
        // eslint-disable-next-line no-global-assign
        global["window"] = {};
    });

    describe("should on adding a stats collector", () => {
        it("creating a new one if not existing.", async () => {
            expect(stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection())).toBeTruthy();
        });

        it("creating only one when trying add the same collector multiple times.", async () => {
            expect(stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection())).toBeTruthy();
            expect(stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection())).toBeFalsy();
            // The User ID is not relevant! Because for stats the call is needed and the user id is for monitoring
            expect(stats.addStatsCollector("CALL_ID", "SOME_OTHER_USER_ID", mockRTCPeerConnection())).toBeFalsy();
        });
    });

    describe("should on removing a stats collector", () => {
        it("returning `true` if the collector exists", async () => {
            expect(stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection())).toBeTruthy();
            expect(stats.removeStatsCollector("CALL_ID")).toBeTruthy();
        });
        it("returning false if the collector not exists", async () => {
            expect(stats.removeStatsCollector("CALL_ID_NOT_EXIST")).toBeFalsy();
        });
    });

    describe("should on get stats collector", () => {
        it("returning `undefined` if collector not existing", async () => {
            expect(stats.getStatsCollector("CALL_ID")).toBeUndefined();
        });

        it("returning Collector if collector existing", async () => {
            expect(stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection())).toBeTruthy();
            expect(stats.getStatsCollector("CALL_ID")).toBeDefined();
        });
    });

    describe("should on start", () => {
        beforeEach(() => {
            jest.useFakeTimers();
            window.setInterval = setInterval;
        });
        afterEach(() => {
            jest.useRealTimers();
            window.setInterval = setInterval;
        });

        it("starting processing as well without stats collectors", async () => {
            // @ts-ignore
            stats.processStats = jest.fn();
            stats.start();
            jest.advanceTimersByTime(TIME_INTERVAL);
            // @ts-ignore
            expect(stats.processStats).toHaveBeenCalled();
        });

        it("starting processing and calling the collectors", async () => {
            stats.addStatsCollector("CALL_ID", "USER_ID", mockRTCPeerConnection());
            const collector = stats.getStatsCollector("CALL_ID");
            if (collector) {
                const processStatsSpy = jest.spyOn(collector, "processStats");
                stats.start();
                jest.advanceTimersByTime(TIME_INTERVAL);
                expect(processStatsSpy).toHaveBeenCalledWith(GROUP_CALL_ID, LOCAL_USER_ID);
            } else {
                throw new Error("Test failed, because no Collector found!");
            }
        });

        it("doing nothing if process already running", async () => {
            // @ts-ignore
            window.setInterval = jest.fn().mockReturnValue(22);
            stats.start();
            expect(window.setInterval).toHaveBeenCalledTimes(1);
            stats.start();
            stats.start();
            stats.start();
            stats.start();
            expect(window.setInterval).toHaveBeenCalledTimes(1);
        });
    });

    describe("should on stop", () => {
        it("finish stats process if was started", async () => {
            // @ts-ignore
            window.setInterval = jest.fn().mockReturnValue(22);
            window.clearInterval = jest.fn();
            stats.start();
            expect(window.setInterval).toHaveBeenCalledTimes(1);
            stats.stop();
            expect(window.clearInterval).toHaveBeenCalledWith(22);
        });

        it("do nothing if stats process was not started", async () => {
            window.clearInterval = jest.fn();
            stats.stop();
            expect(window.clearInterval).not.toHaveBeenCalled();
        });
    });
});

const mockRTCPeerConnection = (): RTCPeerConnection => {
    const pc = {} as RTCPeerConnection;
    pc.addEventListener = jest.fn();
    pc.getStats = jest.fn().mockResolvedValue(null);
    return pc;
};