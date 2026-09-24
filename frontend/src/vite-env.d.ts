/// <reference types="vite/client" />

declare module "*.lottie" {
  const src: string;
  export default src;
}

declare module "*.lottie?url" {
  const src: string;
  export default src;
}

declare module "react-apexcharts" {
  import type { Component } from "react";
  import type { ApexOptions } from "apexcharts";

  export interface Props {
    type?: string;
    series: unknown;
    options?: ApexOptions;
    width?: string | number;
    height?: string | number;
  }

  export default class ReactApexChart extends Component<Props> {}
}
