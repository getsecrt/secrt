import type { JSX } from 'preact';

type IconProps = JSX.SVGAttributes<SVGSVGElement>;

export function CircleQuestionIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 576a256 256 0 1 0 0-512 256 256 0 0 0 0 512m0-336c-18 0-32 14-32 32a24 24 0 1 1-48 0 80 80 0 1 1 160 0c0 47-36 67-56 75v3a24 24 0 1 1-48 0v-8c0-20 15-35 30-40q11-3 18-10 8-6 8-20c0-18-14-32-32-32m-32 192a32 32 0 1 1 64 0 32 32 0 0 1-64 0" />
    </svg>
  );
}

export function TriangleExclamationIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 64q24 1 35 21l216 400a40 40 0 0 1-35 59H104a40 40 0 0 1-35-59L285 85q12-20 35-21m0 352a32 32 0 1 0 0 64 32 32 0 0 0 0-64m0-192c-18 0-33 16-31 34l7 104c1 12 11 22 24 22s23-10 24-22l7-104c2-18-13-34-31-34" />
    </svg>
  );
}

export function CircleXmarkIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 576a256 256 0 1 0 0-512 256 256 0 0 0 0 512m-89-345c9-9 25-9 34 0l55 55 55-55c9-9 25-9 34 0s9 25 0 34l-55 55 55 55c9 9 9 25 0 34-10 9-25 9-34 0l-55-55-55 55c-9 9-25 9-34 0-9-10-9-25 0-34l55-55-55-55c-9-9-9-25 0-34" />
    </svg>
  );
}

export function ClipboardIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M448 96h-9a64 64 0 0 0-55-32H256q-37 2-55 32h-9c-35 0-64 29-64 64v352c0 35 29 64 64 64h256c35 0 64-29 64-64V160c0-35-29-64-64-64m-184 80a24 24 0 1 1 0-48h112a24 24 0 1 1 0 48z" />
    </svg>
  );
}

export function FireIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M257 38c9-8 23-8 31 1q19 17 34 37 22 25 46 64l14-18 3-4c8-10 18-22 31-22s23 12 31 22l4 5q16 19 37 52c28 44 56 107 56 177a224 224 0 0 1-448 0c0-91 41-170 81-225a566 566 0 0 1 80-89zm65 442q37 0 69-21c42-29 53-88 28-134-5-9-16-10-23-2l-25 29c-7 8-19 7-25-1l-65-83c-5-6-15-8-22-1-18 17-51 56-51 104 0 68 51 109 114 109" />
    </svg>
  );
}

export function NoteIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M160 544c-35 0-64-29-64-64V160c0-35 29-64 64-64h320c35 0 64 29 64 64v214q0 26-19 45L419 525a64 64 0 0 1-46 19zm326-176h-94c-13 0-24 11-24 24v94z" />
    </svg>
  );
}

export function UploadIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M352 173v211a32 32 0 1 1-64 0V173l-41 42a32 32 0 0 1-46-46l96-96c13-12 33-12 46 0l96 96a32 32 0 0 1-46 46zm-32 291c44 0 80-36 80-80h80c35 0 64 29 64 64v32c0 35-29 64-64 64H160c-35 0-64-29-64-64v-32c0-35 29-64 64-64h80c0 44 36 80 80 80m144 24a24 24 0 1 0 0-48 24 24 0 1 0 0 48" />
    </svg>
  );
}

export function DownloadIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M352 96a32 32 0 1 0-64 0v211l-41-42a32 32 0 0 0-46 46l96 96c13 12 33 12 46 0l96-96a32 32 0 0 0-46-46l-41 42zM160 384c-35 0-64 29-64 64v32c0 35 29 64 64 64h320c35 0 64-29 64-64v-32c0-35-29-64-64-64h-47l-56 57a80 80 0 0 1-114 0l-56-57zm304 56a24 24 0 1 1 0 48 24 24 0 1 1 0-48" />
    </svg>
  );
}

export function ClockIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 64a256 256 0 1 1 0 512 256 256 0 0 1 0-512m-24 120v136q0 13 11 20l96 64c11 7 26 4 33-7s4-26-7-33l-85-57V184a24 24 0 1 0-48 0" />
    </svg>
  );
}

export function CheckCircleIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 576a256 256 0 1 1 0-512 256 256 0 0 1 0 512m118-366c-11-8-26-6-33 5L285 379l-52-52c-9-9-25-9-34 0-9 10-9 25 0 34l72 72a24 24 0 0 0 36-3l136-187c8-10 6-25-5-33" />
    </svg>
  );
}

export function XMarkIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width={1.7} stroke="currentColor" class="size-5" {...props}>
      <path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12" />
    </svg>
  );
}

export function LockIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M256 160v64h128v-64a64 64 0 0 0-128 0m-64 64v-64a128 128 0 1 1 256 0v64c35 0 64 29 64 64v224c0 35-29 64-64 64H192c-35 0-64-29-64-64V288c0-35 29-64 64-64" />
    </svg>
  );
}

export function EyeIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 96c-81 0-145 37-193 81-46 43-78 95-93 131q-4 12 0 24c15 36 47 88 93 131 48 44 112 81 193 81s146-37 193-81c46-43 78-95 93-131q5-12 0-24c-15-36-47-88-93-131-47-44-112-81-193-81M176 320a144 144 0 1 1 288 0 144 144 0 0 1-288 0m144-64a64 64 0 0 1-96 56q-1 17 3 33a96 96 0 1 0 85-121q8 15 8 32" />
    </svg>
  );
}

export function EyeSlashIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M73 39c-9-9-25-9-34 0-9 10-9 25 0 34l528 528c9 10 25 10 34 0 9-9 9-24 0-34l-96-96 8-7c46-44 78-96 93-131q5-12 0-25c-15-36-47-88-93-131-48-44-112-81-193-81-57 0-106 18-146 44zm164 164q36-26 83-27a144 144 0 0 1 117 228l-34-35a96 96 0 0 0-108-142l-24 10zm120 256a143 143 0 0 1-181-139q0-19 5-37l-80-80c-32 37-55 76-66 105q-6 12 0 24c14 36 46 88 93 131 47 44 111 81 192 81q56-1 102-21z" />
    </svg>
  );
}

export function MenuIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width={1.7} stroke="currentColor" class="size-5" {...props}>
      <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
    </svg>
  );
}

export function UserIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M320 312a120 120 0 1 0 0-240 120 120 0 0 0 0 240m-30 56c-98 0-178 80-178 178 0 17 13 30 30 30h356c17 0 30-13 30-30 0-98-80-178-178-178z" />
    </svg>
  );
}

export function LogoutIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M224 160a32 32 0 1 0 0-64h-64c-53 0-96 43-96 96v256c0 53 43 96 96 96h64a32 32 0 1 0 0-64h-64c-18 0-32-14-32-32V192c0-18 14-32 32-32zm343 183c12-13 12-33 0-46L439 169a32 32 0 0 0-46 46l74 73H256a32 32 0 1 0 0 64h211l-74 73a32 32 0 0 0 46 46z" />
    </svg>
  );
}

export function TableIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M480 96c35 0 64 29 64 64v320c0 35-29 64-64 64H154c-33-4-58-31-58-64V160c0-35 29-64 64-64zM160 384v96h128v-96zm192 0v96h128v-96zm-192-64h128v-96H160zm192 0h128v-96H352z" />
    </svg>
  );
}

export function ChevronDownIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M297 471c13 12 33 12 46 0l192-192a32 32 0 0 0-46-46L320 403 151 233a32 32 0 0 0-46 46z" />
    </svg>
  );
}

export function ChevronUpIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M343 169a32 32 0 0 0-46 0L105 361a32 32 0 0 0 46 46l169-170 169 170a32 32 0 0 0 46-46z" />
    </svg>
  );
}

export function ShuffleIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M468 98q20-7 35 7l64 64a32 32 0 0 1 0 46l-64 64q-15 14-35 6-19-8-20-29v-32h-32q-16 1-26 13l-32 43-40-53 21-29c18-24 47-38 77-38h32v-32q1-21 20-30M218 360l40 53-21 29a96 96 0 0 1-77 38H96a32 32 0 1 1 0-64h64q16 0 26-13zm285 175q-16 14-35 7-19-9-20-30v-32h-32c-30 0-59-14-77-38L186 237q-10-12-26-13H96a32 32 0 1 1 0-64h64c30 0 59 14 77 38l153 205q10 12 26 13h32v-32a32 32 0 0 1 55-23l64 64a32 32 0 0 1 0 46z" />
    </svg>
  );
}

export function PasskeyIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 216 216" fill="currentColor" class="size-5" {...props}>
      <path d="M172.3 96.8c0 13.8-8.5 25.5-20.3 29.8l7.2 11.8-10.6 13 10.6 12.7-17 22.9-12-12.8v-48.5a32 32 0 0 1-18.2-29 31 31 0 0 1 30.2-31.4 31 31 0 0 1 30.1 31.5m-30.2 4.8c4 0 7.3-3.4 7.3-7.6s-3.2-7.6-7.3-7.6-7.2 3.4-7.2 7.6 3.2 7.6 7.2 7.6" />
      <path d="M120.2 131.4A48 48 0 0 1 103 97.2H50.8a20 20 0 0 0-19.8 20v25.3a10 10 0 0 0 9.9 10h69.4a10 10 0 0 0 10-10zm-47-40.3q-3.7-.5-7.2-1.8a25 25 0 0 1-15.3-19.8 33 33 0 0 1 2-19A24 24 0 0 1 72 35.8 29 29 0 0 1 87.4 37a24 24 0 0 1 15 16.2q3.7 12.1-1.5 23.7a24 24 0 0 1-18.4 14l-2 .4z" />
    </svg>
  );
}

export function SquarePlusIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M160 96c-35 0-64 29-64 64v320c0 35 29 64 64 64h320c35 0 64-29 64-64V160c0-35-29-64-64-64zm136 312v-64h-64a24 24 0 1 1 0-48h64v-64a24 24 0 1 1 48 0v64h64a24 24 0 1 1 0 48h-64v64a24 24 0 1 1-48 0" />
    </svg>
  );
}

export function GitHubIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="currentColor" class="size-5" {...props}>
      <path d="M57 85q-20-3-21-22 0-8 4-13c-1-3-1-10 1-12q6-1 11 4l12-2 12 2q5-5 12-4v12q5 5 5 13-1 19-22 22q6 3 6 12v9q0 5 5 4c17-7 30-24 30-45a48 48 0 1 0-96 0c0 21 13 38 31 45q5 1 5-4v-7l-4 1q-9 0-13-10-1-3-4-4l-2-1 4-2q4 0 8 5 3 4 6 4l6-3z" />
    </svg>
  );
}

export function GearIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M259 74c3-15 16-26 31-26h60c15 0 29 11 32 26l14 70q21 9 39 22l68-22q24-6 38 14l30 52c7 13 5 30-7 40l-53 47a188 188 0 0 1 0 46l53 47c12 10 14 27 7 40l-30 52q-14 20-38 14l-68-22q-18 14-39 23l-14 70c-3 14-16 25-32 25h-59c-16 0-29-11-32-25l-14-70q-21-9-39-23l-68 22c-15 5-31-1-38-14l-30-52c-8-13-5-30 6-40l54-47a188 188 0 0 1 0-46l-54-47a32 32 0 0 1-6-40l30-52c7-13 23-19 38-14l67 22q19-13 40-23zm61 326a80 80 0 1 0 0-160 80 80 0 0 0 0 160" />
    </svg>
  );
}

export function KeyIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M400 416a176 176 0 1 0-168-122L71 455q-6 8-7 17v80c0 13 11 24 24 24h80c13 0 24-11 24-24v-40h40c13 0 24-11 24-24v-40h40q10 0 17-7l33-33q26 8 54 8m40-256a40 40 0 1 1 0 80 40 40 0 0 1 0-80" />
    </svg>
  );
}

export function ChevronLeftIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M169 297a32 32 0 0 0 0 46l192 192a32 32 0 0 0 46-46L237 320l170-169a32 32 0 0 0-46-46z" />
    </svg>
  );
}

export function ChevronRightIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M471 297c13 13 13 33 0 46L279 535a32 32 0 0 1-45-46l169-169-169-169a32 32 0 0 1 45-46z" />
    </svg>
  );
}

export function TrashIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="m233 70-9 26h-96a32 32 0 1 0 0 64h384a32 32 0 1 0 0-64h-96l-9-26q-7-21-30-22H263q-22 1-30 22m279 138H128l21 323c2 25 23 45 48 45h246c25 0 46-20 48-45z" />
    </svg>
  );
}

export function AppleIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M447 333q0-55 50-85-28-40-85-45c-35-2-74 21-88 21-15 0-49-20-76-20-56 1-116 45-116 134q0 39 15 81c13 36 59 126 107 125 25-1 43-18 76-18 32 0 48 18 76 18 49-1 91-83 103-119-65-31-62-90-62-92m-56-164c27-33 24-62 24-73-25 1-52 16-68 35a96 96 0 0 0-26 72c26 2 50-12 70-34" />
    </svg>
  );
}

export function WindowsIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="m96 158 184-26v178H96zm0 324 184 26V332H96zm204 28 244 34V332H300zm0-380v180h244V96z" />
    </svg>
  );
}

export function LinuxIcon(props: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" fill="currentColor" class="size-5" {...props}>
      <path d="M516 468q-5-7-7-20t-11-22l-8-5q12-42-3-79c-12-30-32-57-47-75-17-21-34-42-33-72 0-46 5-131-76-131-103 0-77 103-78 135-2 24-6 42-23 65-18 22-45 59-58 97q-9 27-6 53l-16 20q-8 6-17 8-11 3-19 15l-2 24q4 14 1 21-8 20-2 32 6 11 20 12c17 4 41 3 59 12q31 17 56 11 18-5 26-20c13 0 27-6 49-7 14-1 33 5 55 4l2 7c8 17 24 24 40 23q27-2 49-28c13-16 36-23 51-32q12-7 14-18 0-13-16-30M320 151c10-22 34-21 44 0 6 14 3 31-4 40l-13-5 4-4c5-12 0-27-9-27-8-1-14 10-12 23l-13-5q-1-10 3-22m-41-11c10 0 21 14 19 33l-10 5c1-9-3-20-10-20-8 1-9 22-1 28 1 1 2 0-6 6-16-15-11-52 8-52m-13 61s27-25 42-25c7-1 37 13 48 18q14 6 11 18c-3 8-43 34-61 33l-10-2c-8-3-34-25-35-30q-2-7 5-12m3 334c-3 35-44 34-75 18-30-16-69-7-77-22q-4-7 3-27 2-12-1-24-2-12 1-20 5-9 15-11c10-4 12-4 19-10l15-18q7-9 17-7 12 2 22 16l20 36c9 20 43 48 41 69m-2-26-14-20q12 2 17-9c4-34-67-76-71-87q-4-17 0-35c5-23 19-46 27-60q5-3-8 21c-9 16-25 54-3 83q2-32 14-62c12-27 37-75 39-113l19 15q20 14 42 1s34-17 39-24c7 30 25 74 37 96 6 11 18 35 23 64l11 2c14-36-9-68-26-92 13 12 30 34 36 59q5 18 0 36c16 7 36 18 31 35h-5q6-14-22-26c-20-9-36-9-39 12q-16 7-21 28-4 17-4 39l-7 29c-32 23-77 33-115 8m258-12c-1 17-41 20-63 47a67 67 0 0 1-44 25q-21 2-34-19-5-16 1-36c4-15 10-29 10-41q1-22 5-39 3-15 13-21h1c1 13 8 26 19 29 13 3 31-7 38-16 9 0 16-1 23 5 10 8 7 30 17 42q15 17 14 24M269 213s16 19 36 19c27 0 52-28 49-29-1-1-27 23-49 23s-37-20-37-20q-3 1 1 7" />
    </svg>
  );
}
