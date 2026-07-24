import type { AuthenticatedSession } from "@nullstyle/paseto";
import { createDefine } from "fresh";

export interface State {
  session: AuthenticatedSession | null;
}

export const define = createDefine<State>();
