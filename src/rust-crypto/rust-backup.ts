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

import { IKeyBackupCheck, IPreparedKeyBackupVersion, KeyBackupInfo, SecureKeyBackup } from "../crypto-api/keybackup";

export class RustBackupManager implements SecureKeyBackup {
    public async createKeyBackupVersion(info: KeyBackupInfo): Promise<void> {
        //TODO stub
        return;
    }

    public async prepareUnsignedKeyBackupVersion(
        key?: string | Uint8Array | null | undefined,
        algorithm?: string | undefined,
    ): Promise<IPreparedKeyBackupVersion> {
        throw new Error("Method not implemented.");
    }

    public stop(): void {
        throw new Error("Method not implemented.");
    }

    public async checkAndStart(): Promise<IKeyBackupCheck | null> {
        //TODO stub
        return null;
    }

    public getKeyBackupStatus(): string | null {
        //TODO stub
        return null;
    }
}
