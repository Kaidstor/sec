/// <reference types="@raycast/api">

/* 🚧 🚧 🚧
 * This file is auto-generated from the extension's manifest.
 * Do not modify manually. Instead, update the `package.json` file.
 * 🚧 🚧 🚧 */

/* eslint-disable @typescript-eslint/ban-types */

type ExtensionPreferences = {
  /** Sec Binary Path - Путь к бинарю sec. Пусто — автопоиск: /opt/homebrew/bin, /usr/local/bin, ~/go/bin. */
  "secPath"?: string
}

/** Preferences accessible in all the extension's commands */
declare type Preferences = ExtensionPreferences

declare namespace Preferences {
  /** Preferences accessible in the `search-secrets` command */
  export type SearchSecrets = ExtensionPreferences & {}
  /** Preferences accessible in the `add-secret` command */
  export type AddSecret = ExtensionPreferences & {}
  /** Preferences accessible in the `generate-secret` command */
  export type GenerateSecret = ExtensionPreferences & {}
}

declare namespace Arguments {
  /** Arguments passed to the `search-secrets` command */
  export type SearchSecrets = {}
  /** Arguments passed to the `add-secret` command */
  export type AddSecret = {}
  /** Arguments passed to the `generate-secret` command */
  export type GenerateSecret = {}
}

