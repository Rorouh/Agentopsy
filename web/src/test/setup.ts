// Entorno de las pruebas de interfaz: matchers de jest-dom no hacen falta, se
// usan los de vitest sobre el DOM real de jsdom. Lo único que se prepara aquí
// es el desmontaje entre pruebas, para que una no vea el árbol de la anterior.
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
