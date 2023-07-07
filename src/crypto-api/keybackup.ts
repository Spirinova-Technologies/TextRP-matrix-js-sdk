/*
Copyright 2023 The Matrix.org Foundation C.I.C.

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

import { ISigned } from "../@types/signed";
import { DeviceTrustLevel } from "../crypto/CrossSigning";
import { DeviceInfo } from "../crypto/deviceinfo";
import { IKeyBackupInfo } from "../crypto/keybackup";

export interface Curve25519AuthData {
    public_key: string;
    private_key_salt?: string;
    private_key_iterations?: number;
    private_key_bits?: number;
}

export interface Aes256AuthData {
    iv: string;
    mac: string;
    private_key_salt?: string;
    private_key_iterations?: number;
}

/**
 * Extra info of a recovery key
 */
export interface KeyBackupInfo {
    algorithm: string;
    auth_data: ISigned & (Curve25519AuthData | Aes256AuthData);
    count?: number;
    etag?: string;
    version?: string; // number contained within
}

/**
 * Detailed signature information of a backup.
 * This can be used to display what devices/identities are trusting a backup.
 */
export type SigInfo = {
    deviceId: string;
    valid?: boolean | null; // true: valid, false: invalid, null: cannot attempt validation
    device?: DeviceInfo | null;
    crossSigningId?: boolean;
    deviceTrust?: DeviceTrustLevel;
};

/**
 * Backup trust information.
 * Client can upload and download from backup if `usable` is true.
 */
export type TrustInfo = {
    usable: boolean; // is the backup trusted, true iff there is a sig that is valid & from a trusted device
    sigs: SigInfo[];
    // eslint-disable-next-line camelcase
    trusted_locally?: boolean; // true if the private key is known. Notice that this is not enough to use the backup.
};

/**
 * Active key backup info, if any.
 * Returned as a result of `checkAndStart()`.
 */
export interface IKeyBackupCheck {
    backupInfo?: IKeyBackupInfo;
    trustInfo: TrustInfo;
}

export type AuthData = IKeyBackupInfo["auth_data"];

/**
 * Prepared backup data.
 * Contains the data needed to create a new version.
 */
/* eslint-disable camelcase */
export interface IPreparedKeyBackupVersion {
    algorithm: string;
    auth_data: AuthData;
    recovery_key: string;
    privateKey: Uint8Array;
}
/* eslint-enable camelcase */

/**
 * Server side keys backup management.
 * Devices may upload encrypted copies of keys to the server.
 * When a device tries to read a message that it does not have keys for, it may request the key from the server and decrypt it.
 */
export interface SecureKeyBackup {
    /**
     * Gets the status of the current active key backup if any.
     * If there is a usable backup returns the version, if not null.
     */
    getKeyBackupStatus(): string | null;

    /**
     * Stop the SecureKeyBackup manager from backing up keys and allow a clean shutdown.
     */
    stop(): void;

    /**
     * Check the server for an active key backup and
     * if one is present and has a valid signature from
     * one of the user's verified devices, start backing up
     * to it.
     */
    checkAndStart(): Promise<IKeyBackupCheck | null>;

    /**
     * Set up the data required to create a new backup version.  The backup version
     * will not be created and enabled until createKeyBackupVersion is called.
     *
     * @param password - Passphrase string that can be entered by the user
     *     when restoring the backup as an alternative to entering the recovery key.
     *     Optional. If null a random recovery key will be created
     *
     * @returns Object that can be passed to createKeyBackupVersion and
     *     additionally has a 'recovery_key' member with the user-facing recovery key string. The backup data is not yet signed, the cryptoBackend will do it.
     */
    prepareUnsignedKeyBackupVersion(
        key?: string | Uint8Array | null,
        algorithm?: string | undefined,
    ): Promise<IPreparedKeyBackupVersion>;

    createKeyBackupVersion(info: IKeyBackupInfo): Promise<void>;
}
