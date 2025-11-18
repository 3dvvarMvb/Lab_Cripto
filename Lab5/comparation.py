#!/usr/bin/env python3
"""Verifica si el hash (segunda línea) de archivos HASSH aparece en el CSV."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_TXT_DIR = BASE_DIR / "Resultados_cap" / "HASSH"
DEFAULT_CSV = BASE_DIR / "hassh-client.csv"


def load_hassh_index(csv_path: Path) -> Dict[str, Dict[str, str]]:
	"""Carga el CSV en un diccionario indexado por el valor de hassh."""

	if not csv_path.exists():
		raise FileNotFoundError(f"No se encontró el CSV en {csv_path}")

	# Algunos campos (como la lista de versiones) pueden superar el límite por defecto.
	csv.field_size_limit(min(sys.maxsize, 10_000_000))

	index: Dict[str, Dict[str, str]] = {}
	with csv_path.open("r", encoding="utf-8", newline="") as handler:
		reader = csv.DictReader(handler)
		for row in reader:
			hassh = (row.get("hassh") or "").strip().lower()
			if not hassh:
				continue
			index[hassh] = {
				"observations": (row.get("observations") or "").strip(),
				"versions": (row.get("versions") or "").strip(),
			}

	if not index:
		raise ValueError("El CSV no contiene registros válidos.")

	return index


def extract_second_line(txt_path: Path) -> str:
	"""Devuelve la segunda línea del archivo (hash HASSH)."""

	if not txt_path.exists():
		raise FileNotFoundError(f"Archivo no encontrado: {txt_path}")

	with txt_path.open("r", encoding="utf-8") as handler:
		first_line = handler.readline()
		if not first_line:
			raise ValueError(f"El archivo {txt_path} está vacío.")

		second_line = handler.readline().strip()
		if not second_line:
			raise ValueError(
				f"El archivo {txt_path} no contiene una segunda línea con el hash."
			)

	return second_line.lower()


def collect_txt_files(explicit_files: List[Path], fallback_dir: Path) -> List[Path]:
	"""Determina qué archivos TXT procesar."""

	if explicit_files:
		return [path if path.is_absolute() else path.resolve() for path in explicit_files]

	if not fallback_dir.exists():
		raise FileNotFoundError(
			f"No hay archivos proporcionados y el directorio {fallback_dir} no existe."
		)

	files = sorted(fallback_dir.glob("*.txt"))
	if not files:
		raise FileNotFoundError(
			f"No se encontraron archivos .txt dentro de {fallback_dir}"
		)

	return files


def check_files(txt_files: Iterable[Path], hassh_index: Dict[str, Dict[str, str]]) -> List[str]:
	"""Procesa cada archivo y genera líneas de resultado legibles."""

	report: List[str] = []
	for txt in txt_files:
		try:
			hash_value = extract_second_line(txt)
		except (FileNotFoundError, ValueError) as error:
			report.append(f"[ERROR] {txt.name}: {error}")
			continue

		match = hassh_index.get(hash_value)
		if match:
			versions = match["versions"] or "Versiones no especificadas"
			observations = match["observations"] or "Observaciones no registradas"
			report.append(
				"[ENCONTRADO] {file}: hash {hash_} presente en CSV | "
				"obs: {obs} | versiones: {vers}".format(
					file=txt.name,
					hash_=hash_value,
					obs=observations,
					vers=versions,
				)
			)
		else:
			report.append(
				f"[NO ENCONTRADO] {txt.name}: hash {hash_value} no figura en el CSV"
			)

	return report


def parse_arguments() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description=(
			"Verifica si el hash (segunda línea) de uno o más archivos TXT "
			"aparece en el CSV hassh-client."
		)
	)
	parser.add_argument(
		"txt_files",
		nargs="*",
		type=Path,
		help=(
			"Rutas a archivos .txt individuales. Si se omiten, se procesará "
			"todo el contenido de Resultados_cap/HASSH."
		),
	)
	parser.add_argument(
		"--csv",
		dest="csv_path",
		type=Path,
		default=DEFAULT_CSV,
		help=f"Ruta al CSV de referencia (por defecto: {DEFAULT_CSV}).",
	)
	parser.add_argument(
		"--dir",
		dest="txt_dir",
		type=Path,
		default=DEFAULT_TXT_DIR,
		help=(
			"Directorio con archivos .txt a inspeccionar cuando no se pasan "
			"archivos específicos (por defecto: Resultados_cap/HASSH)."
		),
	)
	return parser.parse_args()


def main() -> None:
	args = parse_arguments()

	hassh_index = load_hassh_index(args.csv_path.resolve())
	txt_files = collect_txt_files(
		[path.resolve() for path in args.txt_files], args.txt_dir.resolve()
	)

	results = check_files(txt_files, hassh_index)
	print("Archivo CSV cargado:", args.csv_path)
	for line in results:
		print(line)


if __name__ == "__main__":
	main()
