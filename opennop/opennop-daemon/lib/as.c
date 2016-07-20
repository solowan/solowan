/*

  as.c

  This file is part of OpenNOP-SoloWAN distribution.
  No modifications made from the original file in OpenNOP distribution.

  Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

  References:

    OpenNOP: http://www.opennop.org

  License:

    OpenNOP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include "as.h"
// DFC
#include <strings.h>

// Descriptor de la tabla asociativa
typedef struct {
  size_t   lvalor;     /* Longitud del valor */
  size_t   lreg;       /* Longitud del registro completo */
  size_t   nreg;       /* Número de registros para cálculo de posición */
  char* dreg;       /* Dirección de la zona de almacenamiento  */
} desc;


// Un registro tiene: indicador de vacio/lleno y valor.
typedef enum {
  vacio   = 0,
  lleno   = 1,
} estado;


// Escribe un registro en un sitio



// Funciones públicas

int as_crear (as* pt, size_t nreg, size_t lvalor) {
  desc *das;
  // Pide memoria para el descriptor
  if ((das = (* pt) = malloc (sizeof (desc))) == NULL)
    return 0;
  das->lvalor = lvalor;
  das->nreg   = nreg;
  das->lreg   = lvalor + sizeof (char);
  // Pide memoria para la zona de almacenamiento (rellena con ceros)
  if ((das->dreg = calloc (das->nreg, das->lreg)) == NULL) {
    free (das);
    return 0;
  }
  return 1;
}


int as_cerrar (as t) {
  free (((desc*)t)->dreg);
  free (t);
  return 1;
}


int as_escribir(as t, const size_t pos, const void* pv) {
  desc *das = t;
  char* sitio;
  if (pos >= das->nreg) {
    if ((das->dreg = realloc (das->dreg, pos * das->lreg)) == NULL)
      return 0;
    bzero (das->dreg + (das->lreg * das->nreg), pos - das->nreg);
    das->nreg = pos;
  }
  sitio = das->dreg + (das->lreg * pos);
  * (char*) sitio = lleno;
  bcopy(pv, sitio + sizeof(char), das->lvalor);
  return 1;
}


int as_leer (as t, const size_t pos, void* pv) {
  desc *das = t;
  char* sitio;
  if ((pos >= das->nreg) || (pos < 0))
    return 0;
  if (* (char*) (das->dreg + das->lreg * pos) != lleno)
    return 0;
  sitio = das->dreg + (das->lreg * pos);
  bcopy(sitio + sizeof(char), pv, das->lvalor);
  return 1;
}

int as_borrar (as t, const size_t pos) {
  desc *das = t;
  if ((pos >= das->nreg) || (pos < 0))
    return 0;
  if (* (char*) (das->dreg + (das->lreg * pos)) != lleno)
    return 0;
  * (char*) (das->dreg + (das->lreg * pos)) = lleno;
  return 1;
}

int as_llenos(as t){
	int llenos = 0;
	desc *das = t;
	int i;
	for (i = 0 ; i < das->nreg; i++){
		if (* (char*) (das->dreg + (das->lreg * i)) == lleno)
			llenos++;
	}
	return llenos;
}


