import * as params from "@params";
import { format } from "date-fns";

(() => {
  const { playlist_id, take } = params.default;

  async function handler() {
    const template = `
      <div class="card bg-light">
        <a class="text-body" href="https://www.youtube.com/watch?v=%id%" aria-label="youtube" target="_blank">
          <img class="card-img-top" src="%img_src%" alt="card" />
        </a>
        <div class="card-body pt-4">
          <div class="card-text">
            <p class="text-secondary -text-600">%published%</p>
            <a class="text-body text-decoration-none" href="https://www.youtube.com/watch?v=%id%" target="_blank">
              <h5>%title%</h5>
            </a>
          </div>
        </div>
      </div>`;

    const response = await fetch(
      `/.netlify/functions/youtube-bypass?id=${playlist_id}${
        take ? `&take=${take}` : ""
      }`
    );
    const data = await response.json();
    
    const videoIds = data.map(
      ({ resourceId: { videoId } }) => videoId
    );
    const videosResponse = await fetch(
      `/.netlify/functions/youtube-bypass?type=videos&id=${videoIds.join(
        ","
      )}`
    );
    const videos = await videosResponse.json();

    const el = document.getElementById(playlist_id);

    const items = data
      .map(({ resourceId: { videoId: id }, title, publishedAt, thumbnails }, i) => {
        let tpl = template.replace("%img_src%", thumbnails?.standard?.url);
        tpl = tpl.replaceAll("%id%", id);
        tpl = tpl.replace("%title%", title);
        tpl = tpl.replace(
          "%published%",
          format(new Date(videos[i].publishedAt), "MMM dd, yyyy")
        );
        return tpl.trim();
      })
      .join("");

    el.innerHTML = items;
  }

  handler();
})();
